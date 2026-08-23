use ptah_control::{
    AuthorizedSubmission, ControlKind, HumanControlRequest, HumanSnapshot, authorize_control,
    validate_snapshot,
};
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

const INDEX_HTML: &str = include_str!("../web/index.html");
const PREFLIGHT_JS: &str = include_str!("../web/preflight.js");
const APP_JS: &str = include_str!("../web/app.js");
const STYLES_CSS: &str = include_str!("../web/styles.css");
const MAX_REQUEST_BYTES: usize = 1_048_576;
const REQUEST_IO_TIMEOUT: Duration = Duration::from_secs(2);

pub(crate) struct ServerConfig {
    pub(crate) listen: String,
    pub(crate) snapshot_path: PathBuf,
    pub(crate) submission_path: PathBuf,
}

pub(crate) struct ControlServer {
    config: ServerConfig,
}

impl ControlServer {
    pub(crate) fn new(config: ServerConfig) -> Self {
        Self { config }
    }

    pub(crate) fn run(&self) -> Result<(), String> {
        self.read_snapshot()?;
        if self.config.snapshot_path == self.config.submission_path {
            return Err(String::from(
                "snapshot and submission paths must be different",
            ));
        }
        let listen = validate_loopback_listen(&self.config.listen)?;
        let listener = TcpListener::bind(listen)
            .map_err(|error| format!("cannot bind {}: {error}", self.config.listen))?;
        eprintln!("ptah-control: listening on http://{listen}");
        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    if let Err(error) = self.handle_connection(&mut stream) {
                        eprintln!("ptah-control: request failed: {error}");
                    }
                }
                Err(error) => eprintln!("ptah-control: connection failed: {error}"),
            }
        }
        Ok(())
    }

    fn handle_connection(&self, stream: &mut TcpStream) -> Result<(), String> {
        configure_connection(stream)?;
        let request = match read_request(stream) {
            Ok(request) => request,
            Err(error) => {
                return write_json_error(stream, 400, "bad_request", &error);
            }
        };
        if let Err(error) = validate_request_authority(stream, &request) {
            return write_json_error(stream, 403, "forbidden_origin", &error);
        }
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/") => write_response(stream, 200, "text/html; charset=utf-8", INDEX_HTML),
            ("GET", "/preflight.js") => {
                write_response(stream, 200, "text/javascript; charset=utf-8", PREFLIGHT_JS)
            }
            ("GET", "/app.js") => {
                write_response(stream, 200, "text/javascript; charset=utf-8", APP_JS)
            }
            ("GET", "/styles.css") => {
                write_response(stream, 200, "text/css; charset=utf-8", STYLES_CSS)
            }
            ("GET", "/api/state") => self.write_snapshot(stream),
            ("POST", "/api/control") => self.submit_control(stream, &request.body),
            _ => write_json_error(stream, 404, "not_found", "route not found"),
        }
    }

    fn write_snapshot(&self, stream: &mut TcpStream) -> Result<(), String> {
        let snapshot = match self.read_snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return write_json_error(stream, 503, "state_unavailable", &error);
            }
        };
        let body = serde_json::to_string(&snapshot)
            .map_err(|error| format!("cannot serialize snapshot: {error}"))?;
        write_response(stream, 200, "application/json", &body)
    }

    fn submit_control(&self, stream: &mut TcpStream, body: &[u8]) -> Result<(), String> {
        let snapshot = match self.read_snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return write_json_error(stream, 503, "state_unavailable", &error);
            }
        };
        let request: HumanControlRequest = match serde_json::from_slice(body) {
            Ok(request) => request,
            Err(error) => {
                return write_json_error(
                    stream,
                    400,
                    "invalid_control_request",
                    &error.to_string(),
                );
            }
        };

        if let Err(error) = validate_boundary_request(&snapshot, &request) {
            return write_json_error(stream, 409, "control_rejected", &error);
        }
        let submission = match authorize_control(&snapshot, request.clone()) {
            Ok(submission) => submission,
            Err(error) => {
                return write_json_error(stream, 409, "control_rejected", &error.to_string());
            }
        };

        // Re-read canonical truth immediately before persistence. A UI projection that became stale
        // during request handling is fenced rather than promoted into a dispatchable submission.
        let latest = match self.read_snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return write_json_error(stream, 503, "state_unavailable", &error);
            }
        };
        if latest != snapshot {
            return write_json_error(
                stream,
                409,
                "control_rejected",
                "canonical state changed during authorization; refresh required",
            );
        }

        match request_id_exists(&self.config.submission_path, &submission.request_id) {
            Ok(true) => {
                return write_json_error(
                    stream,
                    409,
                    "control_rejected",
                    "request_id was already submitted",
                );
            }
            Ok(false) => {}
            Err(error) => {
                return write_json_error(stream, 503, "submission_log_unavailable", &error);
            }
        }

        if let Err(error) = append_json_line(&self.config.submission_path, &submission) {
            return write_json_error(stream, 503, "submission_log_unavailable", &error);
        }
        let response = serde_json::to_string(&submission)
            .map_err(|error| format!("cannot serialize submission: {error}"))?;
        write_response(stream, 202, "application/json", &response)
    }

    fn read_snapshot(&self) -> Result<HumanSnapshot, String> {
        let bytes = fs::read(&self.config.snapshot_path).map_err(|error| {
            format!(
                "cannot read snapshot {}: {error}",
                self.config.snapshot_path.display()
            )
        })?;
        let snapshot: HumanSnapshot = serde_json::from_slice(&bytes)
            .map_err(|error| format!("invalid snapshot JSON: {error}"))?;
        validate_snapshot(&snapshot).map_err(|error| format!("snapshot rejected: {error}"))?;
        Ok(snapshot)
    }
}

fn configure_connection(stream: &TcpStream) -> Result<(), String> {
    stream
        .set_read_timeout(Some(REQUEST_IO_TIMEOUT))
        .map_err(|error| format!("cannot set request read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(REQUEST_IO_TIMEOUT))
        .map_err(|error| format!("cannot set response write timeout: {error}"))
}

fn validate_boundary_request(
    current: &HumanSnapshot,
    request: &HumanControlRequest,
) -> Result<(), String> {
    if request.request_id.trim().is_empty() {
        return Err(String::from("request_id must not be blank"));
    }
    if request.kind.requires_explicit_approval()
        && request
            .approval_id
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
    {
        return Err(String::from("explicit caller approval must not be blank"));
    }
    if request.expected.provider_generations != current.authority.provider_generations {
        return Err(String::from("stale provider generation set"));
    }

    match request.kind {
        ControlKind::TerminalInput | ControlKind::TerminalReconnect => {
            let target = current
                .terminals
                .iter()
                .find(|item| item.id == request.target_id)
                .ok_or_else(|| String::from("terminal target is absent"))?;
            validate_target_provider(
                current,
                request,
                &target.provider_id,
                target.provider_generation,
            )
        }
        ControlKind::BrowserNavigate => {
            let target = current
                .browsers
                .iter()
                .find(|item| item.page_id == request.target_id)
                .ok_or_else(|| String::from("browser target is absent"))?;
            validate_target_provider(
                current,
                request,
                &target.provider_id,
                target.provider_generation,
            )
        }
        _ => {
            if request.provider_id.is_some() || request.expected_provider_generation.is_some() {
                return Err(String::from(
                    "provider identity is not valid for this control kind",
                ));
            }
            Ok(())
        }
    }
}

fn validate_target_provider(
    current: &HumanSnapshot,
    request: &HumanControlRequest,
    target_provider_id: &str,
    target_generation: u64,
) -> Result<(), String> {
    if request.provider_id.as_deref() != Some(target_provider_id)
        || request.expected_provider_generation != Some(target_generation)
    {
        return Err(String::from("control target/provider binding mismatch"));
    }
    if current
        .authority
        .provider_generations
        .get(target_provider_id)
        != Some(&target_generation)
    {
        return Err(String::from(
            "current target provider generation is internally inconsistent",
        ));
    }
    Ok(())
}

fn validate_loopback_listen(value: &str) -> Result<SocketAddr, String> {
    let address: SocketAddr = value
        .parse()
        .map_err(|error| format!("invalid listen address {value}: {error}"))?;
    if !address.ip().is_loopback() {
        return Err(String::from(
            "A14 control surface has no remote authentication boundary; listen address must be loopback",
        ));
    }
    Ok(address)
}

fn validate_request_authority(stream: &TcpStream, request: &Request) -> Result<(), String> {
    let local = stream
        .local_addr()
        .map_err(|error| format!("cannot resolve local request authority: {error}"))?;
    validate_loopback_request_authority(
        local.port(),
        &request.method,
        &request.host,
        request.origin.as_deref(),
    )
}

fn validate_loopback_request_authority(
    port: u16,
    method: &str,
    host: &str,
    origin: Option<&str>,
) -> Result<(), String> {
    let allowed_hosts = [
        format!("127.0.0.1:{port}"),
        format!("[::1]:{port}"),
        format!("localhost:{port}"),
    ];
    if !allowed_hosts
        .iter()
        .any(|allowed| host.eq_ignore_ascii_case(allowed))
    {
        return Err(String::from(
            "untrusted Host header for loopback control surface",
        ));
    }

    if method == "POST" && origin.is_none() {
        return Err(String::from(
            "protected POST requires an explicit same-origin Origin header",
        ));
    }
    if let Some(origin) = origin {
        let allowed_origins = [
            format!("http://127.0.0.1:{port}"),
            format!("http://[::1]:{port}"),
            format!("http://localhost:{port}"),
        ];
        if !allowed_origins
            .iter()
            .any(|allowed| origin.eq_ignore_ascii_case(allowed))
        {
            return Err(String::from(
                "untrusted Origin header for loopback control surface",
            ));
        }
    }
    Ok(())
}

struct Request {
    method: String,
    path: String,
    host: String,
    origin: Option<String>,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Result<Request, String> {
    let mut bytes = Vec::with_capacity(8192);
    let mut buffer = [0_u8; 4096];
    let header_end = loop {
        let count = stream
            .read(&mut buffer)
            .map_err(|error| format!("cannot read request: {error}"))?;
        if count == 0 {
            return Err(String::from(
                "client closed before request headers completed",
            ));
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(String::from("request exceeds size limit"));
        }
        if let Some(index) = find_header_end(&bytes) {
            break index;
        }
    };

    let headers = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| String::from("request headers are not valid UTF-8"))?;
    let mut lines = headers.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| String::from("missing request line"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| String::from("missing method"))?
        .to_owned();
    let raw_path = parts.next().ok_or_else(|| String::from("missing path"))?;
    let version = parts
        .next()
        .ok_or_else(|| String::from("missing HTTP version"))?;
    if parts.next().is_some() || !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(String::from("invalid request line"));
    }
    let path = raw_path.split('?').next().unwrap_or(raw_path).to_owned();
    let framing = parse_request_framing(lines)?;
    if framing.content_length > MAX_REQUEST_BYTES {
        return Err(String::from("request body exceeds size limit"));
    }

    let body_start = header_end + 4;
    while bytes.len().saturating_sub(body_start) < framing.content_length {
        let count = stream
            .read(&mut buffer)
            .map_err(|error| format!("cannot read request body: {error}"))?;
        if count == 0 {
            return Err(String::from("client closed before request body completed"));
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.len() > MAX_REQUEST_BYTES + header_end + 4 {
            return Err(String::from("request exceeds size limit"));
        }
    }
    let body_end = body_start + framing.content_length;
    Ok(Request {
        method,
        path,
        host: framing.host,
        origin: framing.origin,
        body: bytes[body_start..body_end].to_vec(),
    })
}

struct RequestFraming {
    content_length: usize,
    host: String,
    origin: Option<String>,
}

fn parse_request_framing<'a>(
    lines: impl Iterator<Item = &'a str>,
) -> Result<RequestFraming, String> {
    let mut content_length = None;
    let mut host = None;
    let mut origin = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(String::from("malformed request header"));
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(String::from("transfer-encoding is not supported"));
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(String::from("duplicate content-length"));
            }
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| String::from("invalid content-length"))?,
            );
        }
        if name.eq_ignore_ascii_case("host") {
            if host.is_some() {
                return Err(String::from("duplicate host header"));
            }
            if value.is_empty() {
                return Err(String::from("host header must not be blank"));
            }
            host = Some(value.to_owned());
        }
        if name.eq_ignore_ascii_case("origin") {
            if origin.is_some() {
                return Err(String::from("duplicate origin header"));
            }
            if value.is_empty() {
                return Err(String::from("origin header must not be blank"));
            }
            origin = Some(value.to_owned());
        }
    }
    let host = host.ok_or_else(|| String::from("missing host header"))?;
    Ok(RequestFraming {
        content_length: content_length.unwrap_or(0),
        host,
        origin,
    })
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn request_id_exists(path: &Path, request_id: &str) -> Result<bool, String> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(format!(
                "cannot open submission log {}: {error}",
                path.display()
            ));
        }
    };
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|error| format!("cannot read submission log: {error}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let submission: AuthorizedSubmission = serde_json::from_str(&line)
            .map_err(|error| format!("submission log contains invalid record: {error}"))?;
        if submission.request_id == request_id {
            return Ok(true);
        }
    }
    Ok(false)
}

fn append_json_line<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create submission directory: {error}"))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("cannot open submission log {}: {error}", path.display()))?;
    serde_json::to_writer(&mut file, value)
        .map_err(|error| format!("cannot encode submission: {error}"))?;
    file.write_all(b"\n")
        .map_err(|error| format!("cannot append submission: {error}"))?;
    file.sync_data()
        .map_err(|error| format!("cannot persist submission: {error}"))
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| String::from("\"serialization_error\""))
}

fn write_json_error(
    stream: &mut TcpStream,
    status: u16,
    code: &str,
    detail: &str,
) -> Result<(), String> {
    let body = format!(
        r#"{{"error":{},"detail":{}}}"#,
        json_string(code),
        json_string(detail)
    );
    write_response(stream, status, "application/json", &body)
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
) -> Result<(), String> {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let headers = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(headers.as_bytes())
        .and_then(|()| stream.write_all(body.as_bytes()))
        .map_err(|error| format!("cannot write response: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ptah_control::{
        AcceptanceState, AdvisoryState, AuthorityStamp, BrowserView, DiagnosticAdvisory,
        EvidenceLink, NodeHealthView, ProviderHealthView, RecoveryView, TerminalView, WorkerView,
    };
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::net::Shutdown;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn snapshot() -> HumanSnapshot {
        HumanSnapshot {
            authority: AuthorityStamp {
                workspace_id: String::from("workspace-1"),
                workspace_revision: 7,
                session_id: String::from("session-1"),
                session_revision: 3,
                node_id: String::from("node-1"),
                node_generation: 9,
                provider_generations: BTreeMap::from([
                    (String::from("terminal-provider"), 4),
                    (String::from("browser-provider"), 8),
                ]),
                fence: String::from("fence-11"),
            },
            workspaces: vec![String::from("workspace-1")],
            activities: Vec::new(),
            objects: Vec::new(),
            terminals: vec![TerminalView {
                id: String::from("terminal-1"),
                activity_id: String::from("activity-1"),
                attached: true,
                provider_id: String::from("terminal-provider"),
                provider_generation: 4,
                limitation: None,
            }],
            transfers: Vec::new(),
            browsers: vec![BrowserView {
                page_id: String::from("page-1"),
                profile_id: String::from("profile-1"),
                url: String::from("https://example.invalid"),
                provider_id: String::from("browser-provider"),
                provider_generation: 8,
                attached: true,
                limitation: None,
            }],
            nodes: vec![NodeHealthView {
                node_id: String::from("node-1"),
                generation: 9,
                health: String::from("healthy"),
                ready: true,
                reachable: true,
                pressure: String::from("normal"),
                evidence: vec![String::from("receipt:node")],
            }],
            providers: vec![ProviderHealthView {
                provider_id: String::from("terminal-provider"),
                generation: 4,
                health: String::from("healthy"),
                limitations: Vec::new(),
                evidence: vec![String::from("receipt:provider")],
            }],
            advisories: vec![DiagnosticAdvisory {
                id: String::from("advisory-1"),
                observed_facts: vec![String::from("capability missing")],
                evidence: vec![String::from("receipt:capability")],
                suggestions: vec![String::from("install capability")],
                uncertainty: None,
                state: AdvisoryState::Open,
            }],
            workers: vec![WorkerView {
                formation_id: String::from("formation-1"),
                worker_id: String::from("worker-1"),
                role: String::from("primary"),
                checkpoint: Some(String::from("checkpoint-1")),
                partial_result: None,
                conflict: None,
                completed: true,
                acceptance: AcceptanceState::Pending,
            }],
            recovery: RecoveryView {
                checkpoint_id: Some(String::from("checkpoint-1")),
                checkpoint_integrity: String::from("verified"),
                restore_compatibility: String::from("compatible"),
                recovery_verification: String::from("verified"),
                limitations: Vec::new(),
            },
            evidence_links: vec![EvidenceLink {
                label: String::from("node proof"),
                reference: String::from("receipt:node"),
            }],
        }
    }

    fn request(kind: ControlKind, target: &str) -> HumanControlRequest {
        let current = snapshot();
        HumanControlRequest {
            request_id: String::from("request-1"),
            kind,
            target_id: String::from(target),
            expected: current.authority,
            provider_id: None,
            expected_provider_generation: None,
            approval_id: None,
            payload: json!({}),
        }
    }

    fn physical_http_response(request: &str) -> String {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after Unix epoch")
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("ptah-a14-http-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&root).expect("temporary A14 HTTP directory must be creatable");
        let snapshot_path = root.join("snapshot.json");
        let submission_path = root.join("submissions.ndjson");
        fs::write(
            &snapshot_path,
            serde_json::to_vec(&snapshot()).expect("snapshot must serialize"),
        )
        .expect("snapshot fixture must be writable");
        fs::write(&submission_path, b"").expect("submission fixture must be writable");

        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback test listener must bind");
        let local = listener
            .local_addr()
            .expect("loopback test listener must expose its address");
        let mut client = TcpStream::connect(local).expect("test client must connect");
        let (mut server_stream, _) = listener.accept().expect("test server must accept");
        let rendered = request.replace("{port}", &local.port().to_string());
        client
            .write_all(rendered.as_bytes())
            .expect("test request must be writable");
        client
            .shutdown(Shutdown::Write)
            .expect("test request write half must close");

        let server = ControlServer::new(ServerConfig {
            listen: local.to_string(),
            snapshot_path,
            submission_path,
        });
        server
            .handle_connection(&mut server_stream)
            .expect("single test request must produce a response");
        drop(server_stream);

        let mut response = String::new();
        client
            .read_to_string(&mut response)
            .expect("test response must be readable");
        fs::remove_dir_all(root).expect("temporary A14 HTTP directory must be removable");
        response
    }

    #[test]
    fn remote_bind_is_rejected_without_authentication_boundary() {
        assert!(validate_loopback_listen("127.0.0.1:7800").is_ok());
        assert!(validate_loopback_listen("[::1]:7800").is_ok());
        assert!(validate_loopback_listen("0.0.0.0:7800").is_err());
    }

    #[test]
    fn accepted_connection_has_bounded_request_io() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback test listener must bind");
        let local = listener
            .local_addr()
            .expect("loopback test listener must expose its address");
        let _client = TcpStream::connect(local).expect("test client must connect");
        let (server_stream, _) = listener.accept().expect("test server must accept");
        configure_connection(&server_stream).expect("connection timeouts must configure");
        assert_eq!(
            server_stream
                .read_timeout()
                .expect("read timeout must query"),
            Some(REQUEST_IO_TIMEOUT)
        );
        assert_eq!(
            server_stream
                .write_timeout()
                .expect("write timeout must query"),
            Some(REQUEST_IO_TIMEOUT)
        );
    }

    #[test]
    fn loopback_http_authority_rejects_dns_rebinding_and_cross_origin_requests() {
        assert!(validate_loopback_request_authority(7800, "GET", "127.0.0.1:7800", None).is_ok());
        assert!(
            validate_loopback_request_authority(
                7800,
                "GET",
                "localhost:7800",
                Some("http://localhost:7800")
            )
            .is_ok()
        );
        assert!(
            validate_loopback_request_authority(7800, "GET", "attacker.invalid:7800", None)
                .is_err()
        );
        assert!(
            validate_loopback_request_authority(
                7800,
                "GET",
                "127.0.0.1:7800",
                Some("https://attacker.invalid")
            )
            .is_err()
        );
        assert!(validate_loopback_request_authority(7800, "POST", "127.0.0.1:7800", None).is_err());
    }

    #[test]
    fn physical_http_boundary_rejects_untrusted_host_origin_and_missing_host() {
        let allowed = physical_http_response(
            "GET /api/state HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n",
        );
        assert!(allowed.starts_with("HTTP/1.1 200 OK\r\n"));

        let attacker_host = physical_http_response(
            "GET /api/state HTTP/1.1\r\nHost: attacker.invalid:{port}\r\nConnection: close\r\n\r\n",
        );
        assert!(attacker_host.starts_with("HTTP/1.1 403 Forbidden\r\n"));
        assert!(attacker_host.contains("forbidden_origin"));

        let attacker_origin = physical_http_response(
            "GET /api/state HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: https://attacker.invalid\r\nConnection: close\r\n\r\n",
        );
        assert!(attacker_origin.starts_with("HTTP/1.1 403 Forbidden\r\n"));
        assert!(attacker_origin.contains("forbidden_origin"));

        let missing_host =
            physical_http_response("GET /api/state HTTP/1.1\r\nConnection: close\r\n\r\n");
        assert!(missing_host.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    }

    #[test]
    fn request_framing_rejects_missing_duplicate_or_blank_authority_headers() {
        assert!(parse_request_framing(["Content-Length: 0"].into_iter()).is_err());
        assert!(parse_request_framing(["Host:   "].into_iter()).is_err());
        assert!(
            parse_request_framing(["Host: 127.0.0.1:7800", "Host: localhost:7800"].into_iter())
                .is_err()
        );
        assert!(
            parse_request_framing(
                [
                    "Host: 127.0.0.1:7800",
                    "Origin: http://127.0.0.1:7800",
                    "Origin: http://localhost:7800",
                ]
                .into_iter()
            )
            .is_err()
        );
        assert!(parse_request_framing(["Host: 127.0.0.1:7800", "Origin:   "].into_iter()).is_err());
    }

    #[test]
    fn stale_provider_set_fences_every_control() {
        let current = snapshot();
        let mut control = request(ControlKind::CheckpointRequest, "workspace-1");
        control
            .expected
            .provider_generations
            .insert(String::from("terminal-provider"), 3);
        assert!(validate_boundary_request(&current, &control).is_err());
    }

    #[test]
    fn terminal_control_is_bound_to_actual_provider() {
        let current = snapshot();
        let mut control = request(ControlKind::TerminalInput, "terminal-1");
        control.provider_id = Some(String::from("browser-provider"));
        control.expected_provider_generation = Some(8);
        assert!(validate_boundary_request(&current, &control).is_err());

        control.provider_id = Some(String::from("terminal-provider"));
        control.expected_provider_generation = Some(4);
        assert!(validate_boundary_request(&current, &control).is_ok());
    }

    #[test]
    fn blank_approval_never_authorizes_upgrade_or_acceptance() {
        let current = snapshot();
        for (kind, target) in [
            (ControlKind::SubmitUpgradeActivity, "advisory-1"),
            (ControlKind::AcceptWorkerResult, "worker-1"),
        ] {
            let mut control = request(kind, target);
            control.approval_id = Some(String::from("   "));
            assert!(validate_boundary_request(&current, &control).is_err());
        }
    }

    #[test]
    fn request_framing_rejects_ambiguous_bodies() {
        let duplicate = [
            "Host: 127.0.0.1:7800",
            "Content-Length: 2",
            "Content-Length: 2",
        ]
        .into_iter();
        assert!(parse_request_framing(duplicate).is_err());
        let chunked = ["Host: 127.0.0.1:7800", "Transfer-Encoding: chunked"].into_iter();
        assert!(parse_request_framing(chunked).is_err());
    }
}
