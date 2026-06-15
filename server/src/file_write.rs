//! Sandboxed `demo.file.write` demo handler (M13.2).
//!
//! A deliberately constrained [`MachineProgram`] that writes a payload's
//! `content` to a `file://` target **only** inside a configured sandbox root.
//! It exists to make M13 permission enforcement concrete and visible — it is a
//! demo handler, **not** production filesystem authority. Path traversal,
//! absolute paths outside the sandbox, symlink escape, and non-`file://` URIs
//! are rejected before any write, each with a typed reason.
//!
//! Production hardening is out of scope and tracked in
//! `docs/issues/secs-magik-phases/demo-file-write-handler.md`: this handler
//! must not be promoted to a production file/resource surface without that
//! checklist (canonicalization policy, symlink policy, payload limits, OS
//! permissions, audit retention, deployment posture).

use crate::gateway::{ExecutionLimits, HandlerOutcome, MachineProgram};
use crate::verifier::VerifiedCallContext;
use async_trait::async_trait;
use serde::Deserialize;
use std::path::{Component, Path, PathBuf};

/// Typed reject reasons. Stable strings for execution-receipt inspection; they
/// describe the failure class only and never echo the payload or target path.
pub mod reject_reason {
    pub const MALFORMED_PAYLOAD: &str = "demo_file_write_malformed_payload";
    pub const NOT_A_FILE_URI: &str = "demo_file_write_not_a_file_uri";
    pub const PATH_TRAVERSAL: &str = "demo_file_write_path_traversal";
    pub const PATH_OUTSIDE_SANDBOX: &str = "demo_file_write_path_outside_sandbox";
    pub const PAYLOAD_TOO_LARGE: &str = "demo_file_write_payload_too_large";
    pub const WRITE_FAILED: &str = "demo_file_write_write_failed";
}

/// Payload contract: `{ "resource": "file:///<sandbox>/...", "content": "..." }`.
#[derive(Debug, Deserialize)]
struct FileWriteRequest {
    resource: String,
    content: String,
}

/// Sandboxed demo file-write handler. Holds the canonical sandbox root; every
/// target must resolve inside it.
pub struct DemoFileWriteProgram {
    sandbox_root: PathBuf,
}

impl DemoFileWriteProgram {
    /// Construct with a sandbox root. The root is canonicalized (resolving
    /// symlinks); returns `None` if it does not exist — the demo must have a
    /// real sandbox directory, so a missing sandbox fails closed at setup.
    pub fn new(sandbox_root: impl AsRef<Path>) -> Option<Self> {
        let sandbox_root = std::fs::canonicalize(sandbox_root).ok()?;
        Some(Self { sandbox_root })
    }

    pub fn sandbox_root(&self) -> &Path {
        &self.sandbox_root
    }

    /// Resolve a `file://` resource to a target path inside the sandbox, or a
    /// typed reject reason. Rejects traversal/`.`/non-absolute/non-`file://`
    /// before touching the filesystem, then resolves the parent (and the target
    /// if it already exists) through `canonicalize` so symlink escape is caught.
    fn resolve_target(&self, resource: &str) -> Result<PathBuf, &'static str> {
        let raw = resource
            .strip_prefix("file://")
            .ok_or(reject_reason::NOT_A_FILE_URI)?;
        let path = Path::new(raw);
        if raw.is_empty() || !path.is_absolute() {
            return Err(reject_reason::NOT_A_FILE_URI);
        }
        for component in path.components() {
            match component {
                Component::ParentDir | Component::CurDir => {
                    return Err(reject_reason::PATH_TRAVERSAL)
                }
                _ => {}
            }
        }

        let file_name = path
            .file_name()
            .ok_or(reject_reason::PATH_OUTSIDE_SANDBOX)?;
        let parent = path.parent().ok_or(reject_reason::PATH_OUTSIDE_SANDBOX)?;

        // The parent must exist and resolve inside the sandbox; canonicalize
        // resolves symlinks so a symlinked parent pointing outside is caught.
        let canonical_parent =
            std::fs::canonicalize(parent).map_err(|_| reject_reason::PATH_OUTSIDE_SANDBOX)?;
        if !canonical_parent.starts_with(&self.sandbox_root) {
            return Err(reject_reason::PATH_OUTSIDE_SANDBOX);
        }

        let target = canonical_parent.join(file_name);
        // If the target already exists (possibly a symlink), it too must resolve
        // inside the sandbox before we write through it.
        if target.exists() {
            let canonical_target =
                std::fs::canonicalize(&target).map_err(|_| reject_reason::PATH_OUTSIDE_SANDBOX)?;
            if !canonical_target.starts_with(&self.sandbox_root) {
                return Err(reject_reason::PATH_OUTSIDE_SANDBOX);
            }
        }
        Ok(target)
    }
}

#[async_trait]
impl MachineProgram for DemoFileWriteProgram {
    async fn execute(
        &self,
        _context: &VerifiedCallContext,
        payload: &[u8],
        limits: ExecutionLimits,
    ) -> HandlerOutcome {
        // The router enforces payload bounds before invocation; this is
        // defensive so the handler stays bounded if called directly.
        if payload.len() > limits.max_payload_bytes {
            return HandlerOutcome::rejected(reject_reason::PAYLOAD_TOO_LARGE);
        }
        let request: FileWriteRequest = match serde_json::from_slice(payload) {
            Ok(request) => request,
            Err(_) => return HandlerOutcome::rejected(reject_reason::MALFORMED_PAYLOAD),
        };
        if request.content.len() > limits.max_output_bytes {
            return HandlerOutcome::rejected(reject_reason::PAYLOAD_TOO_LARGE);
        }
        let target = match self.resolve_target(&request.resource) {
            Ok(target) => target,
            Err(reason) => return HandlerOutcome::rejected(reason),
        };
        match std::fs::write(&target, request.content.as_bytes()) {
            Ok(()) => HandlerOutcome::succeeded_with_output_bytes(request.content.len()),
            Err(_) => HandlerOutcome::rejected(reject_reason::WRITE_FAILED),
        }
    }
}
