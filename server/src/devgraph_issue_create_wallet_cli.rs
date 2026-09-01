//! One-shot loopback Wallet ceremony for exactly `devgraph.issue.create.v1`.
//!
//! The adapter serves one fixed-origin page, accepts one user-activated Wallet
//! presentation, closes its listener, and only then invokes the typed DG-E1
//! producer seam. It is not a generic browser bridge, RPC route, HTTP client,
//! Wallet implementation, or Devgraph mutation surface.

use crate::clock::{failclosed_unix_seconds, is_clock_read_failure};
use crate::devgraph_authority::{encode_base64url, DEVGRAPH_WALLET_PRESENTATION_MAX_JSON_BYTES_V1};
use crate::devgraph_issue_create_cli::{
    canonical_data_root, issue_prepared_exact_producer, prepare_raw_exact_producer_invocation,
    ProducerCliError, ProducerSuccessSummary,
};
use clap::Parser;
use rand::{rngs::OsRng, RngCore};
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout_at, Instant};

pub const WALLET_CEREMONY_BIND_V1: &str = "127.0.0.1:9045";
pub const WALLET_CEREMONY_ORIGIN_V1: &str = "http://127.0.0.1:9045";
pub const WALLET_CEREMONY_URL_V1: &str = "http://127.0.0.1:9045/";
const CSRF_HEADER: &str = "x-secs-csrf";
const PRE_OPEN_SECONDS: u64 = 300;
const SIGNED_WINDOW_SECONDS: u64 = 60;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_REQUEST_BYTES: usize = MAX_HEADER_BYTES + DEVGRAPH_WALLET_PRESENTATION_MAX_JSON_BYTES_V1;
const CONNECTION_READ_SECONDS: u64 = 5;

/// The complete and intentionally non-extensible Wallet command surface.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "secs-devgraph-issue-create-v1-wallet",
    version,
    about = "Approve and issue one fixed devgraph.issue.create.v1 authority projection"
)]
pub struct DevgraphIssueCreateWalletCli {
    /// Owner-private raw canonical Devgraph Issue request.
    #[arg(long, value_name = "FILE")]
    pub request_file: PathBuf,

    /// Owner-private LF-terminated idempotency key file.
    #[arg(long, value_name = "FILE")]
    pub idempotency_key_file: PathBuf,

    /// Absent owner-private create-only output for the signed secS projection.
    #[arg(long, value_name = "FILE")]
    pub signed_projection_output: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletCeremonyError {
    Producer(ProducerCliError),
    BindFailed,
    ClockUnavailable,
    PreOpenExpired,
    SignedWindowExpired,
    Cancelled,
    CeremonyConsumed,
}

impl WalletCeremonyError {
    pub fn reason_code(self) -> &'static str {
        match self {
            Self::Producer(error) => error.reason_code(),
            Self::BindFailed => "wallet_ceremony_bind_failed",
            Self::ClockUnavailable => "wallet_ceremony_clock_unavailable",
            Self::PreOpenExpired => "wallet_ceremony_pre_open_expired",
            Self::SignedWindowExpired => "wallet_ceremony_signed_window_expired",
            Self::Cancelled => "wallet_ceremony_cancelled",
            Self::CeremonyConsumed => "wallet_ceremony_consumed",
        }
    }

    pub fn canonical_json(self) -> String {
        format!("{{\"error\":\"{}\",\"ok\":false}}", self.reason_code())
    }
}

impl fmt::Display for WalletCeremonyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for WalletCeremonyError {}

impl From<ProducerCliError> for WalletCeremonyError {
    fn from(value: ProducerCliError) -> Self {
        Self::Producer(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CeremonyState {
    AwaitingOpen,
    AwaitingWallet { expires_at: u64 },
    Consuming,
    Finished,
}

struct WalletCeremony {
    csrf: Option<String>,
    idempotency_key: String,
    nonce: Option<String>,
    request_json: Vec<u8>,
    session_id: Option<String>,
    state: CeremonyState,
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
    syntactically_valid: bool,
}

struct HttpResponse {
    status: &'static str,
    content_type: &'static str,
    extra_headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

enum HandleOutcome {
    Respond(HttpResponse),
    Submission(Vec<u8>),
    Consumed(HttpResponse, WalletCeremonyError),
}

impl WalletCeremony {
    fn new(request_json: &[u8], idempotency_key: &str) -> Self {
        Self {
            csrf: None,
            idempotency_key: idempotency_key.to_owned(),
            nonce: None,
            request_json: request_json.to_vec(),
            session_id: None,
            state: CeremonyState::AwaitingOpen,
        }
    }

    fn generate_open_secrets(&mut self) {
        let mut session = [0u8; 16];
        let mut nonce = [0u8; 12];
        let mut csrf = [0u8; 32];
        OsRng.fill_bytes(&mut session);
        OsRng.fill_bytes(&mut nonce);
        OsRng.fill_bytes(&mut csrf);
        self.csrf = Some(encode_base64url(&csrf));
        self.nonce = Some(encode_base64url(&nonce));
        self.session_id = Some(encode_base64url(&session));
    }

    fn handle(&mut self, request: HttpRequest, now: u64) -> HandleOutcome {
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/") => self.handle_get(request, now),
            ("POST", "/presentation") => self.handle_post(request, now, false),
            ("POST", "/cancel") => self.handle_post(request, now, true),
            ("GET", "/presentation" | "/cancel") | ("POST", "/") => {
                HandleOutcome::Respond(empty_response("405 Method Not Allowed"))
            }
            _ => HandleOutcome::Respond(empty_response("404 Not Found")),
        }
    }

    fn handle_get(&mut self, request: HttpRequest, now: u64) -> HandleOutcome {
        if self.state != CeremonyState::AwaitingOpen {
            return HandleOutcome::Respond(gone_response());
        }
        if !valid_top_level_get(&request) {
            return HandleOutcome::Respond(empty_response("400 Bad Request"));
        }
        if is_clock_read_failure(now) {
            self.state = CeremonyState::Finished;
            return HandleOutcome::Consumed(
                empty_response("410 Gone"),
                WalletCeremonyError::ClockUnavailable,
            );
        }
        let Some(expires_at) = now.checked_add(SIGNED_WINDOW_SECONDS) else {
            self.state = CeremonyState::Finished;
            return HandleOutcome::Consumed(
                empty_response("410 Gone"),
                WalletCeremonyError::ClockUnavailable,
            );
        };
        self.generate_open_secrets();
        self.state = CeremonyState::AwaitingWallet { expires_at };
        HandleOutcome::Respond(wallet_page_response(
            &self.request_json,
            &self.idempotency_key,
            self.session_id
                .as_deref()
                .expect("valid GET generated session"),
            self.nonce.as_deref().expect("valid GET generated nonce"),
            self.csrf.as_deref().expect("valid GET generated CSRF"),
            now,
            expires_at,
        ))
    }

    fn handle_post(&mut self, request: HttpRequest, now: u64, cancellation: bool) -> HandleOutcome {
        let Some(expected_csrf) = self.csrf.as_deref() else {
            return HandleOutcome::Respond(empty_response("404 Not Found"));
        };
        if request.headers.get(CSRF_HEADER).map(String::as_str) != Some(expected_csrf) {
            return HandleOutcome::Respond(empty_response("404 Not Found"));
        }
        let CeremonyState::AwaitingWallet { expires_at } = self.state else {
            return HandleOutcome::Respond(gone_response());
        };
        if is_clock_read_failure(now) || now >= expires_at {
            self.state = CeremonyState::Finished;
            return HandleOutcome::Consumed(
                gone_response(),
                WalletCeremonyError::SignedWindowExpired,
            );
        }

        // Possession of the exact memory-only CSRF token consumes the one-shot
        // ceremony even when the remainder of the POST is malformed.
        self.state = CeremonyState::Consuming;
        if !valid_wallet_post(&request) || (cancellation && request.body != b"{}") {
            self.state = CeremonyState::Finished;
            return HandleOutcome::Consumed(
                empty_response("400 Bad Request"),
                WalletCeremonyError::CeremonyConsumed,
            );
        }
        if cancellation {
            self.state = CeremonyState::Finished;
            return HandleOutcome::Consumed(
                json_response("200 OK", b"{\"ok\":true}\n".to_vec()),
                WalletCeremonyError::Cancelled,
            );
        }
        HandleOutcome::Submission(request.body)
    }

    fn finish(&mut self) {
        self.state = CeremonyState::Finished;
    }
}

pub async fn run(
    cli: DevgraphIssueCreateWalletCli,
) -> Result<ProducerSuccessSummary, WalletCeremonyError> {
    let data_root = canonical_data_root()?;
    let invocation = prepare_raw_exact_producer_invocation(
        &cli.request_file,
        &cli.idempotency_key_file,
        &cli.signed_projection_output,
        &data_root,
    )?;
    let mut ceremony = WalletCeremony::new(
        invocation.wallet_request_json(),
        invocation.wallet_idempotency_key(),
    );
    let listener = TcpListener::bind(WALLET_CEREMONY_BIND_V1)
        .await
        .map_err(|_| WalletCeremonyError::BindFailed)?;
    eprintln!("Open {WALLET_CEREMONY_URL_V1} in the Wallet-enabled Chrome profile.");

    let pre_open_deadline = Instant::now() + Duration::from_secs(PRE_OPEN_SECONDS);
    let mut signed_deadline = None;
    loop {
        let deadline = signed_deadline.unwrap_or(pre_open_deadline);
        let accepted = timeout_at(deadline, listener.accept()).await;
        let (mut stream, _) = match accepted {
            Ok(Ok(pair)) => pair,
            Ok(Err(_)) => return Err(WalletCeremonyError::BindFailed),
            Err(_) => {
                ceremony.finish();
                return Err(if signed_deadline.is_some() {
                    WalletCeremonyError::SignedWindowExpired
                } else {
                    WalletCeremonyError::PreOpenExpired
                });
            }
        };
        let request = match read_http_request(&mut stream).await {
            Ok(request) => request,
            Err(response) => {
                let _ = write_http_response(&mut stream, &response).await;
                continue;
            }
        };
        let was_awaiting_open = ceremony.state == CeremonyState::AwaitingOpen;
        match ceremony.handle(request, failclosed_unix_seconds()) {
            HandleOutcome::Respond(response) => {
                if was_awaiting_open
                    && matches!(ceremony.state, CeremonyState::AwaitingWallet { .. })
                {
                    signed_deadline =
                        Some(Instant::now() + Duration::from_secs(SIGNED_WINDOW_SECONDS));
                }
                let _ = write_http_response(&mut stream, &response).await;
            }
            HandleOutcome::Consumed(response, error) => {
                drop(listener);
                let _ = write_http_response(&mut stream, &response).await;
                return Err(error);
            }
            HandleOutcome::Submission(presentation) => {
                // This explicit drop is the authority boundary: no receiver
                // config or replay database is opened while the loopback
                // listener can accept another connection.
                drop(listener);
                let result =
                    issue_prepared_exact_producer(invocation, &presentation, &data_root).await;
                ceremony.finish();
                let response = match &result {
                    Ok(_) => json_response(
                        "200 OK",
                        b"{\"ok\":true,\"output_written\":true}\n".to_vec(),
                    ),
                    Err(_) => json_response(
                        "422 Unprocessable Entity",
                        b"{\"error\":\"authority_rejected\",\"ok\":false}\n".to_vec(),
                    ),
                };
                let _ = write_http_response(&mut stream, &response).await;
                return result.map_err(WalletCeremonyError::Producer);
            }
        }
    }
}

fn valid_top_level_get(request: &HttpRequest) -> bool {
    request.syntactically_valid
        && request.body.is_empty()
        && request.headers.get("host").map(String::as_str) == Some(WALLET_CEREMONY_BIND_V1)
        && request.headers.get("sec-fetch-site").map(String::as_str) == Some("none")
        && request.headers.get("sec-fetch-mode").map(String::as_str) == Some("navigate")
        && request.headers.get("sec-fetch-user").map(String::as_str) == Some("?1")
        && request.headers.get("sec-fetch-dest").map(String::as_str) == Some("document")
        && !request.headers.contains_key("origin")
        && !request.headers.contains_key("content-length")
        && !request.headers.contains_key("transfer-encoding")
}

fn valid_wallet_post(request: &HttpRequest) -> bool {
    request.syntactically_valid
        && !request.body.is_empty()
        && request.body.len() <= DEVGRAPH_WALLET_PRESENTATION_MAX_JSON_BYTES_V1
        && request.headers.get("host").map(String::as_str) == Some(WALLET_CEREMONY_BIND_V1)
        && request.headers.get("origin").map(String::as_str) == Some(WALLET_CEREMONY_ORIGIN_V1)
        && request.headers.get("sec-fetch-site").map(String::as_str) == Some("same-origin")
        && request.headers.get("sec-fetch-mode").map(String::as_str) == Some("cors")
        && request.headers.get("sec-fetch-dest").map(String::as_str) == Some("empty")
        && request.headers.get("content-type").map(String::as_str) == Some("application/json")
        && request
            .headers
            .get("content-length")
            .and_then(|value| value.parse::<usize>().ok())
            == Some(request.body.len())
        && !request.headers.contains_key("transfer-encoding")
}

async fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest, HttpResponse> {
    let deadline = Instant::now() + Duration::from_secs(CONNECTION_READ_SECONDS);
    let mut bytes = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if bytes.len() > MAX_HEADER_BYTES {
            return Err(empty_response("431 Request Header Fields Too Large"));
        }
        if let Some(index) = find_bytes(&bytes, b"\r\n\r\n") {
            break index + 4;
        }
        let read = timeout_at(deadline, stream.read(&mut chunk))
            .await
            .map_err(|_| empty_response("408 Request Timeout"))?
            .map_err(|_| empty_response("400 Bad Request"))?;
        if read == 0 {
            return Err(empty_response("400 Bad Request"));
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(empty_response("413 Content Too Large"));
        }
    };
    let header_text = std::str::from_utf8(&bytes[..header_end - 4])
        .map_err(|_| empty_response("400 Bad Request"))?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| empty_response("400 Bad Request"))?;
    let mut request_parts = request_line.split(' ');
    let method = request_parts.next().unwrap_or_default().to_owned();
    let path = request_parts.next().unwrap_or_default().to_owned();
    let version = request_parts.next().unwrap_or_default();
    if request_parts.next().is_some()
        || !matches!(method.as_str(), "GET" | "POST")
        || path.is_empty()
        || version != "HTTP/1.1"
    {
        return Err(empty_response("400 Bad Request"));
    }
    let mut headers = BTreeMap::new();
    let mut syntactically_valid = true;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| empty_response("400 Bad Request"))?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() && byte != b'\t')
        {
            return Err(empty_response("400 Bad Request"));
        }
        let name = name.to_ascii_lowercase();
        let value = value.trim_matches([' ', '\t']).to_owned();
        match headers.entry(name) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(value);
            }
            std::collections::btree_map::Entry::Occupied(_) => {
                syntactically_valid = false;
            }
        }
    }
    let partial_request = |body: Vec<u8>| HttpRequest {
        method: method.clone(),
        path: path.clone(),
        headers: headers.clone(),
        body,
        syntactically_valid: false,
    };
    let content_length = match headers.get("content-length") {
        Some(value) => match value.parse::<usize>() {
            Ok(length) if length <= DEVGRAPH_WALLET_PRESENTATION_MAX_JSON_BYTES_V1 => length,
            // Once a complete header block exposes the valid one-shot CSRF,
            // malformed or oversized length is a consumed POST, not a retry.
            _ => return Ok(partial_request(Vec::new())),
        },
        None => 0,
    };
    let total = header_end
        .checked_add(content_length)
        .ok_or_else(|| empty_response("413 Content Too Large"))?;
    if bytes.len() > total {
        return Ok(partial_request(bytes[header_end..].to_vec()));
    }
    while bytes.len() < total {
        let read = match timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(read)) => read,
            _ => return Ok(partial_request(bytes[header_end..].to_vec())),
        };
        if read == 0 || bytes.len() + read > total {
            return Ok(partial_request(bytes[header_end..].to_vec()));
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    Ok(HttpRequest {
        method,
        path,
        headers,
        body: bytes[header_end..].to_vec(),
        syntactically_valid,
    })
}

async fn write_http_response(
    stream: &mut TcpStream,
    response: &HttpResponse,
) -> std::io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {}\r\nConnection: close\r\nContent-Length: {}\r\nContent-Type: {}\r\n",
        response.status,
        response.body.len(),
        response.content_type
    );
    for (name, value) in &response.extra_headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&response.body).await?;
    stream.shutdown().await
}

fn wallet_page_response(
    request_json: &[u8],
    idempotency_key: &str,
    session_id: &str,
    nonce: &str,
    csrf: &str,
    issued_at: u64,
    expires_at: u64,
) -> HttpResponse {
    let request: serde_json::Value = serde_json::from_slice(request_json)
        .expect("raw request was validated before the Wallet ceremony");
    let payload = serde_json::to_vec(&serde_json::json!({
        "csrf": csrf,
        "expiresAt": expires_at,
        "idempotencyKey": idempotency_key,
        "issuedAt": issued_at,
        "nonce": nonce,
        "request": request,
        "sessionId": session_id
    }))
    .expect("bounded Wallet page payload is serializable");
    let encoded_payload = encode_base64url(&payload);
    let mut csp_nonce = [0u8; 18];
    OsRng.fill_bytes(&mut csp_nonce);
    let csp_nonce = encode_base64url(&csp_nonce);
    let body = format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Castalia Wallet · Devgraph Issue</title>
<style nonce="{csp_nonce}">body{{font:16px system-ui,sans-serif;max-width:44rem;margin:4rem auto;padding:0 1.5rem;color:#171717}}button{{font:inherit;padding:.75rem 1rem}}#status{{margin-top:1rem;white-space:pre-wrap}}</style></head>
<body><main><h1>Authorize one Devgraph Issue</h1><p>This local secS page requests one Wallet signature. It does not contact Devgraph.</p>
<button id="approve" type="button">Review in Castalia Wallet</button><p id="status" role="status">Waiting for your click.</p></main>
<script nonce="{csp_nonce}" data-ceremony="{encoded_payload}">(()=>{{'use strict';const s=document.currentScript;const b=document.getElementById('approve');const o=document.getElementById('status');
const d=JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(s.dataset.ceremony.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.dataset.ceremony.length%4)%4)),c=>c.charCodeAt(0))));
const h={{'Content-Type':'application/json','X-SecS-CSRF':d.csrf}};const cancel=()=>fetch('/cancel',{{method:'POST',cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer',headers:h,body:'{{}}'}}).catch(()=>{{}});
b.addEventListener('click',()=>{{b.disabled=true;o.textContent='Waiting for Wallet approval…';const p=window.castaliaWallet;if(!p||typeof p.requestDevgraphIssueCreatePresentation!=='function'){{o.textContent='Castalia Wallet is not available in this Chrome profile.';void cancel();return;}}
let signed;try{{signed=p.requestDevgraphIssueCreatePresentation({{request:d.request,idempotencyKey:d.idempotencyKey,sessionId:d.sessionId,nonce:d.nonce,issuedAt:d.issuedAt,expiresAt:d.expiresAt}});}}catch(_){{o.textContent='The one-shot ceremony was cancelled. Return to the CLI.';void cancel();return;}}
Promise.resolve(signed).then(x=>fetch('/presentation',{{method:'POST',cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer',headers:h,body:JSON.stringify(x)}})).then(async r=>{{if(!r.ok)throw new Error('local rejection');o.textContent='Signed authority projection written. You may close this tab.';}}).catch(()=>{{o.textContent='The one-shot ceremony was cancelled. Return to the CLI.';void cancel();}});}},{{once:true}});}})();</script></body></html>"#
    )
    .into_bytes();
    HttpResponse {
        status: "200 OK",
        content_type: "text/html; charset=utf-8",
        extra_headers: vec![
            ("Cache-Control", "no-store, max-age=0".to_owned()),
            ("Pragma", "no-cache".to_owned()),
            ("Expires", "0".to_owned()),
            ("X-Content-Type-Options", "nosniff".to_owned()),
            ("X-Frame-Options", "DENY".to_owned()),
            ("Referrer-Policy", "no-referrer".to_owned()),
            ("Cross-Origin-Opener-Policy", "same-origin".to_owned()),
            ("Cross-Origin-Resource-Policy", "same-origin".to_owned()),
            (
                "Permissions-Policy",
                "camera=(), microphone=(), geolocation=(), payment=(), usb=()".to_owned(),
            ),
            (
                "Content-Security-Policy",
                format!("default-src 'none'; script-src 'nonce-{csp_nonce}'; style-src 'nonce-{csp_nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'"),
            ),
        ],
        body,
    }
}

fn empty_response(status: &'static str) -> HttpResponse {
    HttpResponse {
        status,
        content_type: "text/plain; charset=utf-8",
        extra_headers: vec![
            ("Cache-Control", "no-store, max-age=0".to_owned()),
            ("X-Content-Type-Options", "nosniff".to_owned()),
            ("X-Frame-Options", "DENY".to_owned()),
        ],
        body: Vec::new(),
    }
}

fn gone_response() -> HttpResponse {
    empty_response("410 Gone")
}

fn json_response(status: &'static str, body: Vec<u8>) -> HttpResponse {
    HttpResponse {
        status,
        content_type: "application/json",
        extra_headers: vec![("Cache-Control", "no-store, max-age=0".to_owned())],
        body,
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    const NOW: u64 = 1_800_000_000;
    const REQUEST: &[u8] = br#"{"id":"issue-golden","kind":"Issue","title":"Golden Issue"}"#;

    fn get(path: &str) -> HttpRequest {
        HttpRequest {
            method: "GET".to_owned(),
            path: path.to_owned(),
            headers: BTreeMap::from([
                ("host".to_owned(), WALLET_CEREMONY_BIND_V1.to_owned()),
                ("sec-fetch-site".to_owned(), "none".to_owned()),
                ("sec-fetch-mode".to_owned(), "navigate".to_owned()),
                ("sec-fetch-user".to_owned(), "?1".to_owned()),
                ("sec-fetch-dest".to_owned(), "document".to_owned()),
            ]),
            body: Vec::new(),
            syntactically_valid: true,
        }
    }

    fn post(path: &str, csrf: &str, body: &[u8]) -> HttpRequest {
        HttpRequest {
            method: "POST".to_owned(),
            path: path.to_owned(),
            headers: BTreeMap::from([
                ("host".to_owned(), WALLET_CEREMONY_BIND_V1.to_owned()),
                ("origin".to_owned(), WALLET_CEREMONY_ORIGIN_V1.to_owned()),
                ("sec-fetch-site".to_owned(), "same-origin".to_owned()),
                ("sec-fetch-mode".to_owned(), "cors".to_owned()),
                ("sec-fetch-dest".to_owned(), "empty".to_owned()),
                ("content-type".to_owned(), "application/json".to_owned()),
                ("content-length".to_owned(), body.len().to_string()),
                (CSRF_HEADER.to_owned(), csrf.to_owned()),
            ]),
            body: body.to_vec(),
            syntactically_valid: true,
        }
    }

    fn csrf(ceremony: &WalletCeremony) -> String {
        ceremony.csrf.clone().expect("valid GET generated CSRF")
    }

    fn decode_base64url(value: &str) -> Vec<u8> {
        fn sextet(byte: u8) -> u8 {
            match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'-' => 62,
                b'_' => 63,
                _ => panic!("invalid base64url"),
            }
        }
        let mut output = Vec::new();
        for chunk in value.as_bytes().chunks(4) {
            assert_ne!(chunk.len(), 1);
            let mut values = [0u8; 4];
            for (index, byte) in chunk.iter().enumerate() {
                values[index] = sextet(*byte);
            }
            output.push((values[0] << 2) | (values[1] >> 4));
            if chunk.len() >= 3 {
                output.push((values[1] << 4) | (values[2] >> 2));
            }
            if chunk.len() == 4 {
                output.push((values[2] << 6) | values[3]);
            }
        }
        output
    }

    #[test]
    fn cli_has_only_the_three_fixed_file_flags() {
        let mut command = DevgraphIssueCreateWalletCli::command();
        let flags: Vec<_> = command
            .get_arguments()
            .filter_map(|argument| argument.get_long().map(str::to_owned))
            .collect();
        assert_eq!(
            flags,
            [
                "request-file",
                "idempotency-key-file",
                "signed-projection-output"
            ]
        );
        let help = command.render_long_help().to_string();
        for forbidden in [
            "--bind",
            "--port",
            "--origin",
            "--browser",
            "--operation",
            "--audience",
            "--policy",
            "--key",
            "--url",
            "--devgraph",
            "--timeout",
        ] {
            assert!(!help.contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn csrf_session_and_nonce_are_os_random_and_canonical_base64url() {
        let mut first = WalletCeremony::new(REQUEST, "issue-golden-create-0001");
        let mut second = WalletCeremony::new(REQUEST, "issue-golden-create-0001");
        assert!(first.session_id.is_none());
        assert!(first.nonce.is_none());
        assert!(first.csrf.is_none());
        assert!(matches!(
            first.handle(get("/"), NOW),
            HandleOutcome::Respond(_)
        ));
        assert!(matches!(
            second.handle(get("/"), NOW),
            HandleOutcome::Respond(_)
        ));
        assert_eq!(first.session_id.as_ref().unwrap().len(), 22);
        assert_eq!(first.nonce.as_ref().unwrap().len(), 16);
        assert_eq!(first.csrf.as_ref().unwrap().len(), 43);
        assert_ne!(first.session_id, second.session_id);
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.csrf, second.csrf);
        for value in [
            first.session_id.as_ref().unwrap(),
            first.nonce.as_ref().unwrap(),
            first.csrf.as_ref().unwrap(),
        ] {
            assert!(value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte)));
        }
    }

    #[test]
    fn exact_get_returns_hardened_page_then_reload_is_gone() {
        let mut ceremony = WalletCeremony::new(REQUEST, "issue-golden-create-0001");
        let response = match ceremony.handle(get("/"), NOW) {
            HandleOutcome::Respond(response) => response,
            _ => panic!("expected page"),
        };
        assert_eq!(response.status, "200 OK");
        let headers: BTreeMap<_, _> = response.extra_headers.iter().cloned().collect();
        assert_eq!(
            headers.get("Cache-Control").map(String::as_str),
            Some("no-store, max-age=0")
        );
        assert_eq!(
            headers.get("X-Frame-Options").map(String::as_str),
            Some("DENY")
        );
        assert!(headers
            .get("Content-Security-Policy")
            .unwrap()
            .contains("frame-ancestors 'none'"));
        let page = String::from_utf8(response.body).unwrap();
        assert!(page.contains("requestDevgraphIssueCreatePresentation"));
        assert!(page.contains("fetch('/presentation'"));
        assert!(page.contains("fetch('/cancel'"));
        assert!(page.contains("void cancel()"));
        assert!(page.contains("data-ceremony="));
        assert!(!page.contains("issue-golden"));
        assert!(!page.contains("issue-golden-create-0001"));
        assert!(!page.contains("localStorage"));
        assert!(!page.contains("document.cookie"));
        assert!(!page.contains("http://127.0.0.1:9045/?"));
        let marker = "data-ceremony=\"";
        let encoded_start = page.find(marker).unwrap() + marker.len();
        let encoded_end = page[encoded_start..].find('"').unwrap() + encoded_start;
        let payload: serde_json::Value =
            serde_json::from_slice(&decode_base64url(&page[encoded_start..encoded_end])).unwrap();
        assert_eq!(payload["csrf"], ceremony.csrf.as_deref().unwrap());
        assert_eq!(
            payload["sessionId"],
            ceremony.session_id.as_deref().unwrap()
        );
        assert_eq!(payload["nonce"], ceremony.nonce.as_deref().unwrap());
        assert_eq!(payload["issuedAt"], NOW);
        assert_eq!(payload["expiresAt"], NOW + SIGNED_WINDOW_SECONDS);
        assert_eq!(payload["request"]["id"], "issue-golden");
        assert_eq!(payload["idempotencyKey"], "issue-golden-create-0001");

        let reload = match ceremony.handle(get("/"), NOW + 1) {
            HandleOutcome::Respond(response) => response,
            _ => panic!("expected gone"),
        };
        assert_eq!(reload.status, "410 Gone");
    }

    #[test]
    fn invalid_path_and_invalid_csrf_do_not_consume() {
        let mut ceremony = WalletCeremony::new(REQUEST, "issue-golden-create-0001");
        let premature = match ceremony.handle(post("/presentation", "wrong", b"{}"), NOW) {
            HandleOutcome::Respond(response) => response,
            _ => panic!("pre-open POST must not consume"),
        };
        assert_eq!(premature.status, "404 Not Found");
        assert_eq!(ceremony.state, CeremonyState::AwaitingOpen);
        assert!(ceremony.csrf.is_none());

        let invalid_path = match ceremony.handle(get("/favicon.ico"), NOW) {
            HandleOutcome::Respond(response) => response,
            _ => panic!("expected not found"),
        };
        assert_eq!(invalid_path.status, "404 Not Found");
        assert_eq!(ceremony.state, CeremonyState::AwaitingOpen);

        assert!(matches!(
            ceremony.handle(get("/"), NOW),
            HandleOutcome::Respond(_)
        ));
        let invalid = match ceremony.handle(post("/presentation", "wrong", b"{}"), NOW + 1) {
            HandleOutcome::Respond(response) => response,
            _ => panic!("invalid token must not consume"),
        };
        assert_eq!(invalid.status, "404 Not Found");
        assert!(matches!(
            ceremony.state,
            CeremonyState::AwaitingWallet { .. }
        ));
        let csrf = csrf(&ceremony);
        assert!(matches!(
            ceremony.handle(post("/presentation", &csrf, b"{}"), NOW + 1),
            HandleOutcome::Submission(_)
        ));
    }

    #[test]
    fn valid_csrf_malformed_post_consumes_once_and_duplicate_is_gone() {
        let mut ceremony = WalletCeremony::new(REQUEST, "issue-golden-create-0001");
        assert!(matches!(
            ceremony.handle(get("/"), NOW),
            HandleOutcome::Respond(_)
        ));
        let csrf = csrf(&ceremony);
        let mut malformed = post("/presentation", &csrf, b"{}");
        malformed
            .headers
            .insert("origin".to_owned(), "http://localhost:9045".to_owned());
        let consumed = match ceremony.handle(malformed, NOW + 1) {
            HandleOutcome::Consumed(response, error) => (response, error),
            _ => panic!("valid token must consume"),
        };
        assert_eq!(consumed.0.status, "400 Bad Request");
        assert_eq!(consumed.1, WalletCeremonyError::CeremonyConsumed);
        let duplicate = match ceremony.handle(post("/presentation", &csrf, b"{}"), NOW + 1) {
            HandleOutcome::Respond(response) => response,
            _ => panic!("duplicate must be gone"),
        };
        assert_eq!(duplicate.status, "410 Gone");
    }

    #[test]
    fn exact_expiry_is_gone_and_consumed() {
        let mut ceremony = WalletCeremony::new(REQUEST, "issue-golden-create-0001");
        assert!(matches!(
            ceremony.handle(get("/"), NOW),
            HandleOutcome::Respond(_)
        ));
        let csrf = csrf(&ceremony);
        let expired = match ceremony.handle(
            post("/presentation", &csrf, b"{}"),
            NOW + SIGNED_WINDOW_SECONDS,
        ) {
            HandleOutcome::Consumed(response, error) => (response, error),
            _ => panic!("exact expiry must consume"),
        };
        assert_eq!(expired.0.status, "410 Gone");
        assert_eq!(expired.1, WalletCeremonyError::SignedWindowExpired);
    }

    #[test]
    fn exact_wallet_fixture_bytes_cross_the_one_shot_post_unchanged() {
        let wallet =
            include_bytes!("../tests/fixtures/devgraph_issue_create_v1/wallet-presentation.json");
        let mut ceremony = WalletCeremony::new(REQUEST, "issue-golden-create-0001");
        assert!(matches!(
            ceremony.handle(get("/"), NOW),
            HandleOutcome::Respond(_)
        ));
        let csrf = csrf(&ceremony);
        let submitted = match ceremony.handle(post("/presentation", &csrf, wallet), NOW + 1) {
            HandleOutcome::Submission(bytes) => bytes,
            _ => panic!("exact Wallet fixture must be submitted"),
        };
        assert_eq!(submitted, wallet);
        assert_eq!(ceremony.state, CeremonyState::Consuming);
    }

    #[test]
    fn every_top_level_get_binding_is_exact_and_rejection_does_not_open() {
        for header in [
            "host",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-user",
            "sec-fetch-dest",
        ] {
            let mut ceremony = WalletCeremony::new(REQUEST, "issue-golden-create-0001");
            let mut request = get("/");
            request.headers.remove(header);
            let response = match ceremony.handle(request, NOW) {
                HandleOutcome::Respond(response) => response,
                _ => panic!("bad GET must not open"),
            };
            assert_eq!(response.status, "400 Bad Request", "{header}");
            assert_eq!(ceremony.state, CeremonyState::AwaitingOpen, "{header}");
            assert!(ceremony.csrf.is_none(), "{header}");
            assert!(ceremony.session_id.is_none(), "{header}");
            assert!(ceremony.nonce.is_none(), "{header}");
        }

        let mut ceremony = WalletCeremony::new(REQUEST, "issue-golden-create-0001");
        let mut request = get("/");
        request
            .headers
            .insert("origin".to_owned(), WALLET_CEREMONY_ORIGIN_V1.to_owned());
        assert!(matches!(
            ceremony.handle(request, NOW),
            HandleOutcome::Respond(HttpResponse {
                status: "400 Bad Request",
                ..
            })
        ));
        assert_eq!(ceremony.state, CeremonyState::AwaitingOpen);
    }

    #[test]
    fn every_wallet_post_binding_is_exact_and_valid_csrf_consumes() {
        for (header, replacement) in [
            ("host", "localhost:9045"),
            ("origin", "http://localhost:9045"),
            ("sec-fetch-site", "cross-site"),
            ("sec-fetch-mode", "navigate"),
            ("sec-fetch-dest", "document"),
            ("content-type", "application/json; charset=utf-8"),
            ("content-length", "999"),
        ] {
            let mut ceremony = WalletCeremony::new(REQUEST, "issue-golden-create-0001");
            assert!(matches!(
                ceremony.handle(get("/"), NOW),
                HandleOutcome::Respond(_)
            ));
            let csrf = csrf(&ceremony);
            let mut request = post("/presentation", &csrf, b"{}");
            request
                .headers
                .insert(header.to_owned(), replacement.to_owned());
            let response = match ceremony.handle(request, NOW + 1) {
                HandleOutcome::Consumed(response, WalletCeremonyError::CeremonyConsumed) => {
                    response
                }
                _ => panic!("bad POST must consume: {header}"),
            };
            assert_eq!(response.status, "400 Bad Request", "{header}");
            assert_eq!(ceremony.state, CeremonyState::Finished, "{header}");
        }
    }

    #[test]
    fn exact_cancel_consumes_with_one_stable_local_reason_and_no_wallet_text() {
        let mut ceremony = WalletCeremony::new(REQUEST, "issue-golden-create-0001");
        assert!(matches!(
            ceremony.handle(get("/"), NOW),
            HandleOutcome::Respond(_)
        ));
        let csrf = csrf(&ceremony);
        let cancelled = match ceremony.handle(post("/cancel", &csrf, b"{}"), NOW + 1) {
            HandleOutcome::Consumed(response, WalletCeremonyError::Cancelled) => response,
            _ => panic!("exact cancel must consume"),
        };
        assert_eq!(cancelled.status, "200 OK");
        assert_eq!(cancelled.body, b"{\"ok\":true}\n");
        assert_eq!(
            WalletCeremonyError::Cancelled.canonical_json(),
            "{\"error\":\"wallet_ceremony_cancelled\",\"ok\":false}"
        );
        assert_eq!(ceremony.state, CeremonyState::Finished);
    }

    #[test]
    fn cancel_never_accepts_or_echoes_page_supplied_wallet_error_text() {
        let mut ceremony = WalletCeremony::new(REQUEST, "issue-golden-create-0001");
        assert!(matches!(
            ceremony.handle(get("/"), NOW),
            HandleOutcome::Respond(_)
        ));
        let csrf = csrf(&ceremony);
        let private_wallet_text = b"{\"reason\":\"private wallet failure details\"}";
        let response = match ceremony.handle(post("/cancel", &csrf, private_wallet_text), NOW + 1) {
            HandleOutcome::Consumed(response, WalletCeremonyError::CeremonyConsumed) => response,
            _ => panic!("nonempty cancel reason must be rejected and consumed"),
        };
        assert_eq!(response.status, "400 Bad Request");
        assert!(!String::from_utf8_lossy(&response.body).contains("private wallet"));
        assert_eq!(ceremony.state, CeremonyState::Finished);
    }

    #[test]
    fn raw_preflight_does_not_open_or_create_authority_or_replay_state() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let request = temp.path().join("request.json");
        let idempotency = temp.path().join("idempotency.txt");
        let output = temp.path().join("projection.json");
        let missing_data_root = temp.path().join("missing-data-root");
        fs::write(&request, REQUEST).unwrap();
        fs::write(&idempotency, b"issue-golden-create-0001\n").unwrap();
        fs::set_permissions(&request, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&idempotency, fs::Permissions::from_mode(0o600)).unwrap();

        let invocation = prepare_raw_exact_producer_invocation(
            &request,
            &idempotency,
            &output,
            &missing_data_root,
        )
        .unwrap();
        assert_eq!(invocation.wallet_request_json(), REQUEST);
        assert_eq!(
            invocation.wallet_idempotency_key(),
            "issue-golden-create-0001"
        );
        assert!(!missing_data_root.exists());
        assert!(!output.exists());
    }
}
