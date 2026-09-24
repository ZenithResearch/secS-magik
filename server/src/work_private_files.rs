//! Descriptor-relative private files; no symlink or pathname reopen after validation.
use std::{
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path},
};
type Result<T> = std::io::Result<T>;

fn denied() -> std::io::Error {
    std::io::Error::from(std::io::ErrorKind::PermissionDenied)
}

fn open_at(parent: &File, name: &CString, flags: i32, mode: libc::mode_t) -> Result<File> {
    // SAFETY: live directory fd and NUL-terminated name, owned returned fd.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            mode as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(target_os = "macos")]
fn access(file: &File, directory: bool) -> Result<()> {
    use std::ffi::c_void;
    unsafe extern "C" {
        fn acl_get_fd_np(fd: i32, kind: i32) -> *mut c_void;
        fn acl_get_entry(acl: *mut c_void, selector: i32, entry: *mut *mut c_void) -> i32;
        fn acl_get_tag_type(entry: *mut c_void, tag: *mut i32) -> i32;
        fn acl_free(ptr: *mut c_void) -> i32;
    }
    // SAFETY: fstatfs initializes exactly one statfs; ACL handles are retained
    // for iteration and freed once. Every uncertain ACL/mount check fails closed.
    unsafe {
        let mut info = std::mem::MaybeUninit::<libc::statfs>::uninit();
        if libc::fstatfs(file.as_raw_fd(), info.as_mut_ptr()) != 0 {
            return Err(denied());
        }
        if info.assume_init().f_flags & 0x00200000 != 0 {
            return Err(denied());
        }
        let acl = acl_get_fd_np(file.as_raw_fd(), 0x100);
        if acl.is_null() {
            return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                Ok(())
            } else {
                Err(denied())
            };
        }
        let result = (|| {
            let mut selector = 0;
            loop {
                let mut entry = std::ptr::null_mut();
                if acl_get_entry(acl, selector, &mut entry) != 0 {
                    return if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
                        Ok(())
                    } else {
                        Err(denied())
                    };
                }
                let mut tag = 0;
                if !directory || acl_get_tag_type(entry, &mut tag) != 0 || tag != 2 {
                    return Err(denied());
                }
                selector = -1;
            }
        })();
        acl_free(acl);
        result
    }
}

#[cfg(target_os = "linux")]
fn access(file: &File, _directory: bool) -> Result<()> {
    for name in [c"system.posix_acl_access", c"system.posix_acl_default"] {
        // SAFETY: live fd/name; zero-sized null buffer queries attribute size.
        if unsafe { libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) } >= 0
        {
            return Err(denied());
        }
        if !matches!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ENODATA | libc::ENOTSUP)
        ) {
            return Err(denied());
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn protected_mount_root(file: &File) -> bool {
    // A root:wheel mounted volume may be 0775 while this unprivileged user is
    // unable to write it. Do not extend this exception to ordinary ancestors,
    // users in wheel, private leaf directories, or ownership-disabled mounts.
    let Ok(metadata) = file.metadata() else {
        return false;
    };
    if metadata.uid() != 0 || metadata.gid() != 0 || metadata.mode() & 0o002 != 0 {
        return false;
    }
    // SAFETY: the OS fills owned buffers; no user-provided pointer is used.
    unsafe {
        if libc::geteuid() == 0 || libc::getegid() == 0 {
            return false;
        }
        let count = libc::getgroups(0, std::ptr::null_mut());
        if !(0..=1024).contains(&count) {
            return false;
        }
        let mut groups = vec![0; count as usize];
        if libc::getgroups(count, groups.as_mut_ptr()) != count || groups.contains(&0) {
            return false;
        }
        let mut raw = std::mem::MaybeUninit::<libc::statfs>::uninit();
        if libc::fstatfs(file.as_raw_fd(), raw.as_mut_ptr()) != 0 {
            return false;
        }
        let mount = raw.assume_init();
        if mount.f_flags & 0x00200000 != 0 {
            return false;
        }
        let Ok(path) = std::ffi::CStr::from_ptr(mount.f_mntonname.as_ptr()).to_str() else {
            return false;
        };
        let Ok(root) = std::fs::symlink_metadata(path) else {
            return false;
        };
        root.is_dir() && root.dev() == metadata.dev() && root.ino() == metadata.ino()
    }
}

#[cfg(not(target_os = "macos"))]
fn protected_mount_root(_file: &File) -> bool {
    false
}

fn directory(file: &File, private: bool) -> Result<()> {
    let info = file.metadata()?;
    let uid = unsafe { libc::geteuid() };
    let sticky_root = info.uid() == 0 && info.mode() & 0o1000 != 0;
    if !info.is_dir()
        || (info.uid() != uid && info.uid() != 0)
        || (info.mode() & 0o022 != 0 && !sticky_root && !protected_mount_root(file))
        || (private && (info.uid() != uid || info.mode() & 0o077 != 0))
    {
        return Err(denied());
    }
    access(file, true)
}

// Keep all ancestor descriptors alive until the operation completes.
struct Entry {
    directories: Vec<File>,
    name: CString,
}
impl Entry {
    fn open(path: &Path, private_parent: bool) -> Result<Self> {
        if !path.is_absolute() {
            return Err(denied());
        }
        let mut components = path.components();
        if components.next() != Some(Component::RootDir) {
            return Err(denied());
        }
        let mut names = Vec::new();
        for part in components {
            let Component::Normal(name) = part else {
                return Err(denied());
            };
            names.push(CString::new(name.as_bytes()).map_err(|_| denied())?);
        }
        let name = names.pop().ok_or_else(denied)?;
        let mut directories = vec![File::open("/")?];
        directory(&directories[0], false)?;
        for part in names {
            let next = open_at(
                directories.last().unwrap(),
                &part,
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )?;
            directory(&next, false)?;
            directories.push(next);
        }
        directory(directories.last().unwrap(), private_parent)?;
        Ok(Self { directories, name })
    }
    fn parent(&self) -> &File {
        self.directories.last().unwrap()
    }
}

pub fn open(path: &Path, maximum: u64) -> Result<File> {
    let entry = Entry::open(path, false)?;
    let file = open_at(entry.parent(), &entry.name, libc::O_RDONLY, 0)?;
    let info = file.metadata()?;
    if !info.is_file()
        || info.uid() != unsafe { libc::geteuid() }
        || info.mode() & 0o7077 != 0
        || info.nlink() != 1
        || info.len() > maximum
    {
        return Err(denied());
    }
    access(&file, false)?;
    Ok(file)
}

pub fn read(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let file = open(path, maximum)?;
    let info = file.metadata()?;
    // Preallocate the entire bounded read so a secret-bearing Vec cannot be
    // reallocated, leaving an unzeroized old allocation behind.
    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity((maximum + 1) as usize));
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != info.len() || bytes.len() as u64 > maximum {
        return Err(denied());
    }
    Ok(std::mem::take(&mut *bytes))
}

/// Retain a validated private directory and every ancestor during administration.
pub struct Directory(Entry);
impl Directory {
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self(Entry::open(
            &path.join(".directory-validation"),
            true,
        )?))
    }
    pub fn create_child(&self, name: &str) -> Result<()> {
        let name = child_name(name)?;
        if unsafe { libc::mkdirat(self.0.parent().as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        self.0.parent().sync_all()
    }
    /// Atomic publication. Replacements exchange whole private generations;
    /// old generations are retained for diagnosis, never selected by issuance.
    pub fn publish(&self, staged: &str, active: &str, replace: bool) -> Result<()> {
        let staged = child_name(staged)?;
        let active = child_name(active)?;
        let fd = self.0.parent().as_raw_fd();
        #[cfg(target_os = "macos")]
        let result = unsafe {
            unsafe extern "C" {
                fn renameatx_np(
                    a: i32,
                    b: *const libc::c_char,
                    c: i32,
                    d: *const libc::c_char,
                    flags: libc::c_uint,
                ) -> i32;
            }
            renameatx_np(
                fd,
                staged.as_ptr(),
                fd,
                active.as_ptr(),
                if replace { 2 } else { 4 },
            )
        };
        #[cfg(target_os = "linux")]
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                fd,
                staged.as_ptr(),
                fd,
                active.as_ptr(),
                if replace { 2 } else { 1 },
            ) as i32
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
        self.0.parent().sync_all()
    }
}
fn child_name(name: &str) -> Result<CString> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(denied());
    }
    CString::new(name).map_err(|_| denied())
}

/// One stable lock outside exchanged generations; fail busy instead of waiting
/// while an agent or maintenance process owns the authority operation.
pub fn lock(path: &Path, exclusive: bool) -> Result<File> {
    let entry = Entry::open(path, true)?;
    let file = open_at(
        entry.parent(),
        &entry.name,
        libc::O_RDWR | libc::O_CREAT,
        0o600,
    )?;
    let info = file.metadata()?;
    if !info.is_file()
        || info.uid() != unsafe { libc::geteuid() }
        || info.mode() & 0o7077 != 0
        || info.nlink() != 1
    {
        return Err(denied());
    }
    access(&file, false)?;
    if unsafe {
        libc::flock(
            file.as_raw_fd(),
            libc::LOCK_NB
                | if exclusive {
                    libc::LOCK_EX
                } else {
                    libc::LOCK_SH
                },
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(file)
}

pub struct Output(Entry);
impl Output {
    pub fn prepare(path: &Path) -> Result<Self> {
        let entry = Entry::open(path, true)?;
        let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: live fd/name and valid output storage; no following links.
        if unsafe {
            libc::fstatat(
                entry.parent().as_raw_fd(),
                entry.name.as_ptr(),
                info.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0
            || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT)
        {
            return Err(denied());
        }
        Ok(Self(entry))
    }

    pub fn write(self, bytes: &[u8]) -> Result<()> {
        let entry = self.0;
        let mut random = [0; 16];
        rand::RngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut random).map_err(|_| denied())?;
        let name = CString::new(format!(
            ".secs-work-{}.tmp",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ))
        .unwrap();
        let mut file = open_at(
            entry.parent(),
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        let result = (|| {
            access(&file, false)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            // SAFETY: relative names refer to one held private directory.
            // linkat publishes complete bytes atomically and cannot overwrite.
            if unsafe {
                libc::linkat(
                    entry.parent().as_raw_fd(),
                    name.as_ptr(),
                    entry.parent().as_raw_fd(),
                    entry.name.as_ptr(),
                    0,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        })();
        // SAFETY: unlink only the temporary entry we created in the held dir.
        let removed = unsafe { libc::unlinkat(entry.parent().as_raw_fd(), name.as_ptr(), 0) };
        result?;
        if removed != 0 {
            return Err(std::io::Error::last_os_error());
        }
        entry.parent().sync_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    #[test]
    fn output_uses_held_parent_after_a_path_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let parent = root.join("private");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let output = Output::prepare(&parent.join("output.json")).unwrap();
        fs::rename(&parent, root.join("held")).unwrap();
        fs::create_dir(&parent).unwrap();
        output.write(b"complete bytes").unwrap();
        assert_eq!(
            fs::read(root.join("held/output.json")).unwrap(),
            b"complete bytes"
        );
        assert!(!parent.join("output.json").exists());
        assert_eq!(fs::read_dir(root.join("held")).unwrap().count(), 1);
    }

    #[test]
    fn output_race_preserves_existing_bytes_and_removes_its_temp() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("output.json");
        let output = Output::prepare(&path).unwrap();
        fs::write(&path, b"other writer").unwrap();
        assert!(output.write(b"our bytes").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"other writer");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
    }
}
