//! Closed local administration RPC. OS-local dispatch does not grant authority.
//! No HTTP, network socket, caller-selected executable, key custody or shell.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use castalia_wallet_presentation::{decode_hex, parse};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
pub type Result<T> = std::result::Result<T, &'static str>;
pub const MAX: usize = 65_536; // protected configuration only
pub const REQUEST_MAX: usize = 524_288;
pub const RESPONSE_MAX: usize = 1_048_576;
fn local_receiver(value: &str) -> bool {
    let Some((host, port)) = value
        .strip_prefix("https://")
        .and_then(|s| s.split_once(':'))
    else {
        return false;
    };
    let Ok(address) = host.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let Ok(port) = port.parse::<u16>() else {
        return false;
    };
    port >= 1024
        && (address == std::net::Ipv4Addr::LOCALHOST || address.is_private())
        && value == format!("https://{address}:{port}")
}
fn receiver_schema_allowed(schema: &str, value: &str) -> bool {
    match schema {
        "secs.local-admin-config.v1" => {
            local_receiver(value) && value.starts_with("https://127.0.0.1:")
        }
        "secs.local-admin-config.v2" => local_receiver(value),
        "secs.local-admin-config.v3" => {
            value.starts_with("https://")
                && castalia_wallet_presentation::Caller {
                    kind: "browser".into(),
                    id: value.into(),
                }
                .validate()
                .is_ok()
        }
        _ => false,
    }
}
const DOMAIN: &[u8] = b"castalia/access-request-approval/v1\0";
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub schema: String,
    pub resource_id: String,
    pub instance_id: String,
    pub receiver: String,
    pub issuer: String,
    pub profile_sha256: String,
    pub rpc_binary_sha256: String,
    pub python: PathBuf,
    pub python_sha256: String,
    pub source: PathBuf,
    pub runtime: PathBuf,
    pub data_root: PathBuf,
    pub name: String,
    pub source_files: BTreeMap<String, String>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: String,
    pub request_id: String,
    pub resource_id: String,
    pub instance_id: String,
    pub receiver: String,
    pub issuer: String,
    pub profile_sha256: String,
    pub operation: String,
    pub body: Value,
}
fn id(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
            }
        })
}
fn object_keys(v: &Value, keys: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|m| m.len() == keys.len() && keys.iter().all(|k| m.contains_key(*k)))
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().ok_or("invalid_request")
}
fn canonical(v: &Value, depth: usize) -> Result<Vec<u8>> {
    if depth > 16 {
        return Err("invalid_request");
    }
    match v {
        Value::Object(m) => {
            let mut entries = Vec::new();
            let mut keys: Vec<_> = m.keys().collect();
            keys.sort();
            for k in keys {
                if !k.is_ascii() {
                    return Err("invalid_request");
                };
                let key = serde_json::to_string(k).map_err(|_| "invalid_request")?;
                entries.push([key.as_bytes(), b":", &canonical(&m[k], depth + 1)?].concat());
            }
            Ok([b"{".as_slice(), &entries.join(b",".as_slice()), b"}"].concat())
        }
        Value::Array(a) => {
            let items: Result<Vec<_>> = a.iter().map(|x| canonical(x, depth + 1)).collect();
            Ok([b"[".as_slice(), &items?.join(b",".as_slice()), b"]"].concat())
        }
        Value::Number(n)
            if n.as_i64()
                .is_none_or(|x| x.unsigned_abs() > 9_007_199_254_740_991) =>
        {
            Err("invalid_request")
        }
        _ => serde_json::to_vec(v).map_err(|_| "invalid_request"),
    }
}
impl Request {
    pub fn check(&self, c: &Configuration, now: u64) -> Result<()> {
        if self.schema != "secs.local-admin-request.v1"
            || !id(&self.request_id)
            || self.resource_id != c.resource_id
            || self.instance_id != c.instance_id
            || self.receiver != c.receiver
            || self.issuer != c.issuer
            || self.profile_sha256 != c.profile_sha256
        {
            return Err("receiver_changed");
        }
        if canonical(&self.body, 0)?.len() > REQUEST_MAX {
            return Err("invalid_request");
        }
        if matches!(
            self.operation.as_str(),
            "service_challenge" | "service_execute"
        ) {
            return Err("service_binding_required");
        }
        match self.operation.as_str() {
            "inspect" => {
                if self.body != json!({}) {
                    return Err("invalid_request");
                };
            }
            "challenge" => {
                if !object_keys(
                    &self.body,
                    &["subject_public_key", "installation_id", "action"],
                ) {
                    return Err("invalid_request");
                }
                decode_hex::<32>(text(&self.body, "subject_public_key")?)?;
                decode_hex::<16>(text(&self.body, "installation_id")?)?;
                action(&self.body["action"])?;
            }
            "execute" => {
                if !object_keys(&self.body, &["challenge", "signature"]) {
                    return Err("invalid_request");
                }
                let ch = &self.body["challenge"];
                if !object_keys(
                    ch,
                    &[
                        "schema",
                        "challenge_id",
                        "nonce",
                        "issuer",
                        "receiver",
                        "subject_public_key",
                        "installation_id",
                        "operation",
                        "issued_at",
                        "expires_at",
                        "details",
                    ],
                ) || text(ch, "schema")? != "castalia.access-request-challenge.v1"
                    || text(ch, "issuer")? != c.issuer
                    || text(ch, "receiver")? != c.receiver
                {
                    return Err("receiver_changed");
                }
                decode_hex::<16>(text(ch, "challenge_id")?)?;
                decode_hex::<16>(text(ch, "installation_id")?)?;
                let nonce = text(ch, "nonce")?;
                if nonce.len() != 43
                    || URL_SAFE_NO_PAD
                        .decode(nonce)
                        .map_err(|_| "invalid_request")?
                        .len()
                        != 32
                {
                    return Err("invalid_request");
                }
                let start = ch["issued_at"].as_u64().ok_or("invalid_request")?;
                let end = ch["expires_at"].as_u64().ok_or("invalid_request")?;
                if start > now || end <= now || end.checked_sub(start) != Some(120) {
                    return Err("approval_expired");
                }
                if !object_keys(
                    &ch["details"],
                    &["action", "policy_revision", "policy_digest_sha256"],
                ) {
                    return Err("invalid_request");
                }
                let op = action(&ch["details"]["action"])?;
                if text(ch, "operation")? != op {
                    return Err("operation_changed");
                }
                let sig = text(&self.body, "signature")?;
                let bytes = URL_SAFE_NO_PAD
                    .decode(sig)
                    .map_err(|_| "invalid_signature")?;
                if sig.len() != 86 || URL_SAFE_NO_PAD.encode(&bytes) != sig {
                    return Err("invalid_signature");
                }
                let signature = Signature::from_slice(&bytes).map_err(|_| "invalid_signature")?;
                let key =
                    VerifyingKey::from_bytes(&decode_hex::<32>(text(ch, "subject_public_key")?)?)
                        .map_err(|_| "invalid_signature")?;
                let encoded = canonical(ch, 0)?;
                if encoded.len() > 131_072 {
                    return Err("invalid_request");
                }
                key.verify_strict(&[DOMAIN, &encoded].concat(), &signature)
                    .map_err(|_| "invalid_signature")?;
            }
            _ => return Err("operation_unavailable"),
        }
        Ok(())
    }
}
fn action(v: &Value) -> Result<&'static str> {
    let name = text(v, "action")?;
    if !v.is_object() || decode_hex::<16>(text(v, "action_id")?).is_err() {
        return Err("invalid_request");
    }
    match name {
        "inbox" => Ok("access.inbox"),
        "review" => Ok("access.review"),
        "approve" | "deny" | "revoke" | "upgrade_arena_policy" | "create_arena" => Ok("access.decide"),
        "status" | "arena_policy_status" | "arena_create_status" => Ok("access.status"),
        _ => Err("operation_unavailable"),
    }
}
pub fn digest(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}
fn safe_path(path: &Path, home: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute()
        || path.components().any(|p| {
            matches!(
                p,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err("unsafe_configuration");
    }
    let mut next = PathBuf::new();
    for part in path.components() {
        next.push(part);
        let m = std::fs::symlink_metadata(&next).map_err(|_| "setup_required")?;
        if m.file_type().is_symlink()
            || m.mode() & 0o022 != 0
            || !(m.uid() == 0 || m.uid() == unsafe { libc::geteuid() })
        {
            return Err("unsafe_configuration");
        }
    }
    if !path.starts_with(home) {
        return Err("unsafe_configuration");
    };
    Ok(())
}
pub fn private_file(path: &Path, home: &Path, maximum: usize) -> Result<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    safe_path(path, home)?;
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "setup_required")?;
    let m = f.metadata().map_err(|_| "setup_required")?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
        || m.nlink() != 1
        || m.len() > maximum as u64
    {
        return Err("unsafe_configuration");
    }
    let mut raw = Vec::new();
    (&mut f)
        .take(maximum as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| "setup_required")?;
    if raw.len() > maximum {
        return Err("unsafe_configuration");
    };
    Ok(raw)
}
pub fn load(home: &Path, instance: &str) -> Result<Configuration> {
    load_internal(home, instance, false)
}
pub fn load_v3(home: &Path, instance: &str) -> Result<Configuration> {
    load_internal(home, instance, true)
}
fn load_internal(home: &Path, instance: &str, v3: bool) -> Result<Configuration> {
    if !id(instance) {
        return Err("invalid_instance");
    }
    let path = home.join(".zenith/rpc/v1").join(format!("{instance}.json"));
    let c: Configuration = parse(&private_file(&path, home, MAX)?, MAX)?;
    if (v3 && c.schema != "secs.local-admin-config.v3")
        || (!v3
            && !["secs.local-admin-config.v1", "secs.local-admin-config.v2"]
                .contains(&c.schema.as_str()))
        || c.instance_id != instance
        || !id(&c.resource_id)
        || !receiver_schema_allowed(&c.schema, &c.receiver)
        || c.source_files.is_empty()
        || c.source_files.len() > 1024
    {
        return Err("unsafe_configuration");
    }
    decode_hex::<32>(&c.profile_sha256)?;
    let binary = match c.schema.as_str() {
        "secs.local-admin-config.v3" => "secs-local-admin-rpc-v3",
        "secs.local-admin-config.v2" => "secs-local-admin-rpc-v2",
        _ => "secs-local-admin-rpc-v1",
    };
    let executable = home
        .join("Library/Application Support/Zenith/secS/bin")
        .join(binary);
    safe_path(&executable, home)?;
    if digest(&std::fs::read(executable).map_err(|_| "setup_required")?) != c.rpc_binary_sha256 {
        return Err("executable_changed");
    }
    if !c
        .source_files
        .contains_key("devgraph/ops/local_admin_rpc.py")
    {
        return Err("handler_unavailable");
    }
    safe_path(&c.source, home)?;
    // Reuse the existing deployment's venv interpreter, whose final component
    // may be its normal symlink to the pinned OS/package-manager Python. The
    // invoking account owns the private venv path; dependency custody is the
    // same as the already-running HTTPS deployment, not new caller input.
    safe_path(c.python.parent().ok_or("unsafe_configuration")?, home)?;
    let executable = std::fs::canonicalize(&c.python).map_err(|_| "setup_required")?;
    let metadata = std::fs::metadata(&executable).map_err(|_| "setup_required")?;
    use std::os::unix::fs::MetadataExt;
    if !metadata.is_file()
        || metadata.mode() & 0o022 != 0
        || ![0, unsafe { libc::geteuid() }].contains(&metadata.uid())
    {
        return Err("unsafe_configuration");
    }
    if digest(&std::fs::read(&c.python).map_err(|_| "setup_required")?) != c.python_sha256 {
        return Err("executable_changed");
    }
    for (name, hash) in &c.source_files {
        let path = Path::new(name);
        if path.is_absolute()
            || path
                .components()
                .any(|p| !matches!(p, std::path::Component::Normal(_)))
        {
            return Err("unsafe_configuration");
        }
        let file = c.source.join(path);
        safe_path(&file, home)?;
        if digest(&std::fs::read(file).map_err(|_| "setup_required")?) != *hash {
            return Err("handler_changed");
        }
    }
    private_file(&c.runtime, home, MAX)?;
    Ok(c)
}
// Nonblocking pipes retain the deadline even after the direct handler exits
// with an inherited pipe still open in a descendant. No unbounded thread joins.
fn bounded_output(mut child: Child, raw: &[u8], timeout: Duration) -> Result<Vec<u8>> {
    use std::io::ErrorKind;
    use std::os::fd::AsRawFd;
    let result = (|| {
        let mut input = Some(child.stdin.take().ok_or("handler_unavailable")?);
        let mut output = child.stdout.take().ok_or("handler_unavailable")?;
        for fd in [input.as_ref().unwrap().as_raw_fd(), output.as_raw_fd()] {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            {
                return Err("handler_unavailable");
            }
        }
        let deadline = Instant::now() + timeout;
        let (mut offset, mut bytes, mut eof, mut status) = (0, Vec::new(), false, None);
        loop {
            if Instant::now() >= deadline {
                return Err("result_unknown");
            }
            if offset == raw.len() {
                input.take();
            }
            if let Some(stream) = input.as_mut() {
                match stream.write(&raw[offset..]) {
                    Ok(n) if n > 0 => offset += n,
                    Err(e)
                        if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
                    _ => return Err("result_unknown"),
                }
            }
            if !eof {
                let mut buffer = [0; 8192];
                match output.read(&mut buffer) {
                    Ok(0) => eof = true,
                    Ok(n) => {
                        bytes.extend_from_slice(&buffer[..n]);
                        if bytes.len() > RESPONSE_MAX {
                            return Err("result_unknown");
                        }
                    }
                    Err(e)
                        if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
                    _ => return Err("result_unknown"),
                }
            }
            if status.is_none() {
                status = child.try_wait().map_err(|_| "result_unknown")?;
            }
            if let (Some(exit), true) = (status, eof) {
                return if exit.success() && offset == raw.len() {
                    Ok(bytes)
                } else {
                    Err("result_unknown")
                };
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    })();
    if result.is_err() {
        // The child is created in its own process group, never the caller's.
        // Kill descendants holding pipes as well as the direct handler.
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
        let _ = child.kill();
        let _ = child.try_wait();
    }
    result
}
/// Validate a canonical operation against an independently pinned public issuer.
/// The transport envelope is unchanged; only the signed inner receiver is canonical.
fn check_service(
    c: &Configuration,
    request: &Request,
    pin: &secs_grant_contract::IssuerPin,
    now: u64,
) -> Result<()> {
    let mut outer = request.clone();
    outer.operation = "inspect".into();
    outer.body = json!({});
    outer.check(c, now)?;
    if !object_keys(&request.body, &["service_access_point", "request"]) {
        return Err("invalid_request");
    }
    let binding: secs_grant_contract::AccessPointBinding =
        serde_json::from_value(request.body["service_access_point"].clone())
            .map_err(|_| "invalid_service_binding")?;
    secs_grant_contract::verify_access_point(pin, &binding, &c.receiver, now)
        .map_err(|_| "invalid_service_binding")?;
    let mut canonical = c.clone();
    canonical.receiver = binding.claims.authority_receiver;
    let mut inner = request.clone();
    inner.receiver = canonical.receiver.clone();
    inner.operation = match request.operation.as_str() {
        "service_challenge" => "challenge",
        "service_execute" => "execute",
        _ => return Err("invalid_request"),
    }
    .into();
    inner.body = request.body["request"].clone();
    inner.check(&canonical, now)
}
fn service_pin(c: &Configuration, home: &Path) -> Result<secs_grant_contract::IssuerPin> {
    let path = home
        .join(".zenith/services/v1")
        .join(format!("{}.json", c.instance_id));
    let service: Value = parse(&private_file(&path, home, MAX)?, MAX)?;
    let profile = &service["connection"];
    if service["resource_id"] != c.resource_id
        || service["instance_id"] != c.instance_id
        || service["interface"] != "wallet-api"
        || service["endpoint"] != c.receiver
        || profile["receiver"] != c.receiver
        || profile["issuer"] != c.issuer
        || digest(&canonical(profile, 0)?) != c.profile_sha256
    {
        return Err("receiver_changed");
    }
    let authority = &profile["authority"];
    let pin = secs_grant_contract::IssuerPin {
        issuer: c.issuer.clone(),
        key_id: text(authority, "key_id")?.into(),
        public_key: text(authority, "public_key")?.into(),
        service: format!("devgraph:{}", c.resource_id),
    };
    if authority["issuer"] != pin.issuer {
        return Err("receiver_changed");
    }
    decode_hex::<32>(&pin.public_key)?;
    Ok(pin)
}
/// Bounded caller input, including a caller that keeps stdin open indefinitely.
pub fn read_request(fd: i32, deadline: Duration) -> Result<Vec<u8>> {
    let until = Instant::now() + deadline;
    let mut raw = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let remaining = until.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("invalid_request");
        }
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe {
            libc::poll(
                &mut poll,
                1,
                remaining.as_millis().min(i32::MAX as u128) as i32,
            )
        };
        if ready < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err("invalid_request");
        }
        if ready == 0 || poll.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err("invalid_request");
        }
        let count = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if count == 0 {
            return Ok(raw);
        }
        if count < 0 {
            return Err("invalid_request");
        }
        raw.extend_from_slice(&buffer[..count as usize]);
        if raw.len() > REQUEST_MAX {
            return Err("invalid_request");
        }
    }
}
pub fn invoke(c: &Configuration, request: &Request, home: &Path) -> Result<Value> {
    invoke_deadline(c, request, home, Instant::now() + Duration::from_secs(30))
}
pub fn invoke_deadline(
    c: &Configuration,
    request: &Request,
    home: &Path,
    deadline: Instant,
) -> Result<Value> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "clock_unavailable")?
        .as_secs();
    if matches!(
        request.operation.as_str(),
        "service_challenge" | "service_execute"
    ) {
        check_service(c, request, &service_pin(c, home)?, now)?;
    } else {
        request.check(c, now)?;
    }
    let config = home
        .join(".zenith/rpc/v1")
        .join(format!("{}.json", c.instance_id));
    let script = "import runpy,sys;sys.path.insert(0,sys.argv[1]);runpy.run_module('devgraph.ops.local_admin_rpc',run_name='__main__')";
    use std::os::unix::process::CommandExt;
    let child = Command::new(&c.python)
        .args(["-I", "-c", script])
        .arg(&c.source)
        .arg(config)
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LANG", "en_US.UTF-8")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("DEVGRAPH_DATA_ROOT", &c.data_root)
        .env("DEVGRAPH_SIGNED_READ_CONFIG", &c.runtime)
        .env("NEO4J_URI", "bolt://127.0.0.1:7687")
        .env("NEO4J_USER", "neo4j")
        .env("NEO4J_DATABASE", "neo4j")
        .env(
            "NEO4J_PASSWORD_FILE",
            c.data_root.join("secrets/neo4j_password"),
        )
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "handler_unavailable")?;
    let raw = serde_json::to_vec(request).map_err(|_| "invalid_request")?;
    let bytes = bounded_output(
        child,
        &raw,
        deadline.saturating_duration_since(Instant::now()),
    )?;
    let value: Value = parse(&bytes, RESPONSE_MAX)?;
    if value["schema"] != "secs.local-admin-response.v1"
        || value["request_id"] != request.request_id
        || value["resource_id"] != c.resource_id
        || value["instance_id"] != c.instance_id
        || value["receiver"] != c.receiver
    {
        return Err("response_changed");
    }
    Ok(value)
}
pub fn response(request: &Request, value: Value) -> Value {
    json!({"schema":"secs.local-admin-response.v1","request_id":request.request_id,"resource_id":request.resource_id,"instance_id":request.instance_id,"receiver":request.receiver,"status":200,"body":value})
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn config() -> Configuration {
        Configuration {
            schema: "secs.local-admin-config.v1".into(),
            resource_id: "00000000-0000-4000-8000-000000000010".into(),
            instance_id: "00000000-0000-4000-8000-000000000011".into(),
            receiver: "https://127.0.0.1:18443".into(),
            issuer: "fixture".into(),
            profile_sha256: "ab".repeat(32),
            rpc_binary_sha256: "cd".repeat(32),
            python: "/not/executed".into(),
            python_sha256: "ef".repeat(32),
            source: "/not/executed".into(),
            runtime: "/not/executed".into(),
            data_root: "/not/executed".into(),
            name: "Fixture".into(),
            source_files: BTreeMap::new(),
        }
    }
    fn request(operation: &str, body: Value) -> Request {
        let c = config();
        Request {
            schema: "secs.local-admin-request.v1".into(),
            request_id: "00000000-0000-4000-8000-000000000001".into(),
            resource_id: c.resource_id,
            instance_id: c.instance_id,
            receiver: c.receiver,
            issuer: c.issuer,
            profile_sha256: c.profile_sha256,
            operation: operation.into(),
            body,
        }
    }
    fn signed() -> Request {
        let key = SigningKey::from_bytes(&[7; 32]);
        let ch = json!({"schema":"castalia.access-request-challenge.v1","challenge_id":"ab".repeat(16),"nonce":URL_SAFE_NO_PAD.encode([3;32]),"issuer":"fixture","receiver":config().receiver,"subject_public_key":hex::encode(key.verifying_key().as_bytes()),"installation_id":"cd".repeat(16),"operation":"access.inbox","issued_at":100,"expires_at":220,"details":{"action":{"schema":"devgraph.access-operator-action.v1","action_id":"ef".repeat(16),"action":"inbox"},"policy_revision":1,"policy_digest_sha256":"ab".repeat(32)}});
        let sig = key.sign(&[DOMAIN, &canonical(&ch, 0).unwrap()].concat());
        request(
            "execute",
            json!({"challenge":ch,"signature":URL_SAFE_NO_PAD.encode(sig.to_bytes())}),
        )
    }
    #[test]
    fn service_binding_keeps_exact_transport_and_signed_receiver() {
        use secs_grant_contract::{AccessPointClaims, IssuerPin, issue_access_point};
        let key = SigningKey::from_bytes(&[1; 32]);
        let pin = IssuerPin {
            issuer: "fixture".into(),
            key_id: "key:v1".into(),
            public_key: hex::encode(key.verifying_key().as_bytes()),
            service: "service:fixture".into(),
        };
        let mut config = config();
        config.receiver = "https://route.example".into();
        let binding = issue_access_point(
            &pin,
            AccessPointClaims {
                schema: secs_grant_contract::ACCESS_POINT.into(),
                issuer: pin.issuer.clone(),
                key_id: pin.key_id.clone(),
                service: pin.service.clone(),
                origin: config.receiver.clone(),
                authority_receiver: signed().receiver,
                prefix: "/service/v1".into(),
                not_before: 100,
                not_after: 1000,
            },
            &key,
            101,
        )
        .unwrap();
        let mut request = signed();
        request.operation = "service_execute".into();
        request.receiver = config.receiver.clone();
        request.body = json!({"service_access_point":binding,"request":request.body});
        assert!(check_service(&config, &request, &pin, 101).is_ok());
        request.body["service_access_point"]["claims"]["authority_receiver"] =
            json!("https://evil.example");
        assert!(check_service(&config, &request, &pin, 101).is_err());
    }
    #[test]
    fn owner_arena_commands_remain_signed_and_operation_bound() {
        for (name, operation) in [("upgrade_arena_policy", "access.decide"), ("arena_policy_status", "access.status")] {
            let key = SigningKey::from_bytes(&[7; 32]);
            let mut r = signed();
            r.body["challenge"]["operation"] = json!(operation);
            r.body["challenge"]["details"]["action"] = json!({"schema":"devgraph.access-operator-action.v10","action":name,"action_id":"ef".repeat(16),"arena_read_ids":["research"]});
            let sig = key.sign(&[DOMAIN, &canonical(&r.body["challenge"], 0).unwrap()].concat());
            r.body["signature"] = json!(URL_SAFE_NO_PAD.encode(sig.to_bytes()));
            assert!(r.check(&config(), 101).is_ok());
            r.body["challenge"]["details"]["action"]["arena_read_ids"] = json!(["private"]);
            assert!(r.check(&config(), 101).is_err());
        }
    }
    #[test]
    fn initial_input_has_a_deadline() {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        assert!(read_request(fds[0], Duration::from_millis(20)).is_err());
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }
    #[test]
    fn valid_wallet_proof_admitted_without_network_or_host_exception() {
        assert!(signed().check(&config(), 101).is_ok())
    }
    #[test]
    fn wrong_receiver_and_instance_rejected() {
        let mut r = signed();
        r.instance_id = "00000000-0000-4000-8000-000000000002".into();
        assert!(r.check(&config(), 101).is_err());
        r = signed();
        r.body["challenge"]["receiver"] = json!("https://other.example");
        assert!(r.check(&config(), 101).is_err())
    }
    #[test]
    fn changed_action_and_signature_rejected() {
        let mut r = signed();
        r.body["challenge"]["details"]["action"]["action"] = json!("approve");
        assert_eq!(r.check(&config(), 101), Err("operation_changed"));
        r = signed();
        r.body["signature"] = json!("A".repeat(86));
        assert!(r.check(&config(), 101).is_err())
    }
    #[test]
    fn expired_future_and_wrong_lifetime_rejected() {
        assert!(signed().check(&config(), 99).is_err());
        assert!(signed().check(&config(), 220).is_err());
        let mut r = signed();
        r.body["challenge"]["expires_at"] = json!(221);
        assert!(r.check(&config(), 101).is_err())
    }
    #[test]
    fn challenge_has_closed_input_and_no_authority() {
        let body = json!({"subject_public_key":"ab".repeat(32),"installation_id":"cd".repeat(16),"action":{"action":"inbox","action_id":"ef".repeat(16)}});
        let mut r = request("challenge", body);
        assert!(r.check(&config(), 101).is_ok());
        r.body["executable"] = json!("/bin/sh");
        assert!(r.check(&config(), 101).is_err())
    }
    #[test]
    fn service_and_shell_commands_not_inferred_from_admin_role() {
        for op in ["deploy", "shell", "configure", "admin", "sign"] {
            assert!(request(op, json!({})).check(&config(), 101).is_err())
        }
    }
    #[test]
    fn duplicate_unknown_and_nonportable_json_rejected() {
        assert!(parse::<Request>(b"{\"schema\":1,\"schema\":2}", MAX).is_err());
        assert!(parse::<Value>(b"{\"n\":1.2}", MAX).is_err());
        assert!(parse::<Value>(b"{\"n\":9007199254740992}", MAX).is_err());
        let mut r = signed();
        r.body["challenge"]["details"]["extra"] = json!(1);
        assert!(r.check(&config(), 101).is_err())
    }
    #[test]
    fn canonical_matches_python_key_order_and_unicode() {
        assert_eq!(
            canonical(&json!({"z":"é","a":[true,null,5]}), 0).unwrap(),
            "{\"a\":[true,null,5],\"z\":\"é\"}".as_bytes()
        )
    }
    #[test]
    fn python_wallet_signature_vector_matches_native_verifier() {
        let body: Value = parse(
            include_bytes!("../tests/fixtures/python-wallet-proof.json"),
            MAX,
        )
        .unwrap();
        assert!(request("execute", body).check(&config(), 101).is_ok());
    }
    #[test]
    fn private_configuration_rejects_symlinks_shared_modes_and_oversize() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let home = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(format!("test-private-{}", std::process::id()));
        std::fs::create_dir(&home).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        let file = home.join("record.json");
        std::fs::write(&file, b"{}").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(private_file(&file, &home, 2).is_ok());
        assert!(private_file(&file, &home, 1).is_err());
        let link = home.join("linked.json");
        symlink(&file, &link).unwrap();
        assert!(private_file(&link, &home, 2).is_err());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(private_file(&file, &home, 2).is_err());
        std::fs::remove_file(&link).unwrap();
        std::fs::remove_file(&file).unwrap();
        std::fs::remove_dir(&home).unwrap();
    }
    #[test]
    fn local_receiver_is_canonical_private_ipv4_only() {
        for value in [
            "https://127.0.0.1:18443",
            "https://192.168.50.10:18443",
            "https://10.0.0.1:4443",
        ] {
            assert!(local_receiver(value));
        }
        for value in [
            "https://8.8.8.8:18443",
            "http://192.168.50.10:18443",
            "https://192.168.50.10:80",
            "https://192.168.50.10:018443",
            "https://192.168.50.10:18443/path",
            "https://example.test:18443",
            "https://192.168.50.10:18443@8.8.8.8",
        ] {
            assert!(!local_receiver(value));
        }
    }
    #[test]
    fn secondary_https_is_explicit_v3_without_relaxing_old_versions() {
        for origin in [
            "https://graph.example.ts.net:9443",
            "https://graph.example.test",
            "https://192.168.50.10:18443",
        ] {
            assert!(receiver_schema_allowed(
                "secs.local-admin-config.v3",
                origin
            ));
        }
        for schema in ["secs.local-admin-config.v1", "secs.local-admin-config.v2"] {
            for origin in [
                "https://graph.example.ts.net:9443",
                "https://graph.example.test",
            ] {
                assert!(!receiver_schema_allowed(schema, origin));
            }
        }
        for origin in [
            "http://graph.example.test",
            "https://GRAPH.example.test",
            "https://graph.example.test/",
            "https://graph.example.test:443",
            "https://graph.example.test/path",
            "https://user@graph.example.test",
            "https://graph.example.test?next=evil",
            "https://graph.example.test.",
        ] {
            assert!(
                !receiver_schema_allowed("secs.local-admin-config.v3", origin),
                "{origin}"
            );
        }
    }
    #[test]
    fn secondary_wallet_signature_still_binds_exact_receiver() {
        let mut c = config();
        c.schema = "secs.local-admin-config.v3".into();
        c.receiver = "https://graph.example.ts.net:9443".into();
        let mut r = signed();
        r.receiver = c.receiver.clone();
        // Rebinding an old challenge is never sufficient.
        assert!(r.check(&c, 101).is_err());
        let key = SigningKey::from_bytes(&[7; 32]);
        r.body["challenge"]["receiver"] = json!(c.receiver);
        let signature = key.sign(&[DOMAIN, &canonical(&r.body["challenge"], 0).unwrap()].concat());
        r.body["signature"] = json!(URL_SAFE_NO_PAD.encode(signature.to_bytes()));
        assert!(r.check(&c, 101).is_ok());
        r.profile_sha256 = "00".repeat(32);
        assert_eq!(r.check(&c, 101), Err("receiver_changed"));
    }
    #[test]
    fn inherited_pipe_and_blocked_input_respect_the_total_deadline() {
        use std::os::unix::process::CommandExt;
        for script in [
            "sleep 10 & exit 0",
            "sleep 10",
            "while :; do printf abcdefgh; done",
        ] {
            let child = Command::new("/bin/sh")
                .args(["-c", script])
                .process_group(0)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let start = Instant::now();
            assert_eq!(
                bounded_output(child, &[0; MAX], Duration::from_millis(100)),
                Err("result_unknown")
            );
            assert!(start.elapsed() < Duration::from_secs(2));
        }
    }
    #[test]
    fn response_binds_original_call() {
        let r = signed();
        let v = response(&r, json!({}));
        assert_eq!(v["instance_id"], config().instance_id);
        assert_eq!(v["request_id"], r.request_id);
        assert_eq!(v["receiver"], r.receiver)
    }
}
