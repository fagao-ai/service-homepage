use axum::extract::{Path as AxPath, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, put};
use axum::{routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

#[derive(Serialize, Deserialize, Clone)]
struct Service {
    id: String,
    name: String,
    #[serde(default)]
    icon: String,
    /// Port ("8080"), port+path ("5200/docs"), local path ("/x") or full URL.
    url: String,
    #[serde(default)]
    desc: String,
}

#[derive(Deserialize)]
struct ServiceIn {
    name: String,
    #[serde(default)]
    icon: String,
    url: String,
    #[serde(default)]
    desc: String,
}

/// Per-IP login throttle: 5 consecutive failures -> 60s lockout.
#[derive(Default)]
struct Attempts {
    fails: u32,
    blocked_until: Option<std::time::Instant>,
}

#[derive(Clone)]
struct AppState {
    services: Arc<RwLock<Vec<Service>>>,
    path: PathBuf,
    attempts: Arc<Mutex<std::collections::HashMap<String, Attempts>>>,
    /// Cached liveness from the last web-port probe: port -> up.
    health: Arc<RwLock<std::collections::HashMap<u16, bool>>>,
    /// Long-lived session token handed out after login.
    token: String,
    /// None disables auth entirely.
    password: Option<String>,
    user: String,
}

/// Constant-time-ish password compare (lengths differ => early false).
fn check_password(input: &str, expect: &str) -> bool {
    if input.len() != expect.len() {
        return false;
    }
    input
        .bytes()
        .zip(expect.bytes())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

async fn login_page() -> Html<&'static str> {
    Html(include_str!("login.html"))
}

#[derive(Deserialize)]
struct LoginIn {
    user: String,
    password: String,
}

fn client_ip(headers: &axum::http::HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

async fn login(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<LoginIn>,
) -> Response {
    let ip = client_ip(&headers);
    // Lockout check before validating credentials.
    {
        let map = st.attempts.lock().unwrap();
        if let Some(a) = map.get(&ip) {
            if let Some(until) = a.blocked_until {
                if std::time::Instant::now() < until {
                    return (
                        StatusCode::TOO_MANY_REQUESTS,
                        "too many failed attempts, wait a minute",
                    )
                        .into_response();
                }
            }
        }
    }

    let ok = st
        .password
        .as_deref()
        .is_some_and(|p| input.user == st.user && check_password(&input.password, p));
    {
        let mut map = st.attempts.lock().unwrap();
        if ok {
            map.remove(&ip);
        } else {
            let a = map.entry(ip).or_default();
            a.fails += 1;
            if a.fails >= 5 {
                a.blocked_until = Some(std::time::Instant::now() + Duration::from_secs(60));
                a.fails = 0;
            }
        }
    }
    if !ok {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let value = format!(
        "hp_session={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000",
        st.token
    );
    (
        [(header::SET_COOKIE, HeaderValue::from_str(&value).unwrap())],
        StatusCode::NO_CONTENT,
    )
        .into_response()
}

async fn auth(State(st): State<AppState>, req: Request, next: Next) -> Response {
    // No password configured: serve the site read-only. Mutations and power
    // ops stay disabled so a missing env file can never expose shutdown.
    if st.password.is_none() {
        let writable = *req.method() != axum::http::Method::GET;
        let sensitive = req.uri().path() == "/api/power";
        if writable || sensitive {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "read-only: set HOME_PASSWORD to enable edits and power ops",
            )
                .into_response();
        }
        return next.run(req).await;
    }
    let path = req.uri().path().to_string();
    if path == "/login" || path == "/api/login" {
        return next.run(req).await;
    }
    let ok = req
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(';')
                .any(|c| c.trim() == format!("hp_session={}", st.token))
        })
        .unwrap_or(false);
    if ok {
        next.run(req).await
    } else if path.starts_with("/api/") {
        StatusCode::UNAUTHORIZED.into_response()
    } else {
        axum::response::Redirect::to("/login").into_response()
    }
}

fn persist(state: &AppState) {
    let list = state.services.read().unwrap().clone();
    if let Ok(json) = serde_json::to_string_pretty(&list) {
        // Write to a temp file then rename so a crash/shutdown mid-write
        // can never truncate the real file.
        let tmp = state.path.with_extension("json.tmp");
        let ok = fs::write(&tmp, json)
            .and_then(|()| fs::rename(&tmp, &state.path))
            .map_err(|e| eprintln!("persist failed: {e}"));
        let _ = ok;
    }
}

/// Create a file with owner-only permissions (token material).
fn write_secret(path: &PathBuf, content: &str) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    use std::io::Write as _;
    f.write_all(content.as_bytes())
}

fn new_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{nanos:x}")
}

/// Extract the local port from a service URL for liveness matching.
fn service_port(url: &str) -> Option<u16> {
    let rest = url.trim();
    let candidate = if let Some(r) = rest.strip_prefix("http://") {
        r
    } else if rest.starts_with("https://") {
        return None; // remote URL, unknown
    } else {
        rest
    };
    // "8080", "8080/path", "host:8080/path"
    let token = candidate.split('/').next().unwrap_or("");
    let port_str = token.rsplit(':').next().unwrap_or("");
    if port_str.is_empty() || !token.contains(':') && port_str.parse::<u16>().is_err() {
        // bare path like "/x"
        return None;
    }
    port_str.parse().ok()
}

#[derive(Serialize)]
struct ServiceOut {
    #[serde(flatten)]
    service: Service,
    /// True/false: probed state; null: unknown/not yet probed.
    up: Option<bool>,
}

async fn list(State(st): State<AppState>) -> Json<Vec<ServiceOut>> {
    let health = st.health.read().unwrap().clone();
    let out = st
        .services
        .read()
        .unwrap()
        .iter()
        .map(|s| ServiceOut {
            up: service_port(&s.url).and_then(|p| health.get(&p).copied()),
            service: s.clone(),
        })
        .collect();
    Json(out)
}

async fn add(
    State(st): State<AppState>,
    Json(input): Json<ServiceIn>,
) -> (StatusCode, Json<Service>) {
    let svc = Service {
        id: new_id(),
        name: input.name,
        icon: input.icon,
        url: input.url,
        desc: input.desc,
    };
    st.services.write().unwrap().push(svc.clone());
    persist(&st);
    (StatusCode::CREATED, Json(svc))
}

async fn update(
    State(st): State<AppState>,
    AxPath(id): AxPath<String>,
    Json(input): Json<ServiceIn>,
) -> StatusCode {
    {
        let mut list = st.services.write().unwrap();
        let Some(svc) = list.iter_mut().find(|s| s.id == id) else {
            return StatusCode::NOT_FOUND;
        };
        svc.name = input.name;
        svc.icon = input.icon;
        svc.url = input.url;
        svc.desc = input.desc;
    }
    persist(&st);
    StatusCode::NO_CONTENT
}

async fn remove(State(st): State<AppState>, AxPath(id): AxPath<String>) -> StatusCode {
    let mut list = st.services.write().unwrap();
    let before = list.len();
    list.retain(|s| s.id != id);
    if list.len() == before {
        return StatusCode::NOT_FOUND;
    }
    drop(list);
    persist(&st);
    StatusCode::NO_CONTENT
}

/// Root-owned infra ports invisible to `ss -tlnp` without sudo (caddy admin,
/// easytier rpc/metrics); never valid homepage entries.
const KNOWN_INFRA: [u16; 3] = [2019, 11010, 15888];

#[derive(Serialize, Clone)]
struct ListeningPort {
    port: u16,
    addr: String,
    process: Option<String>,
    pid: Option<u32>,
}

/// Enumerate listening TCP sockets via `ss -tlnp`. Owned processes expose
/// their names; other users' processes only show the port (no privilege).
/// Parse `ss -tlnp` output into candidate listener entries, applying port and
/// process-name filters. Pure so unit tests can feed fixture text.
fn parse_ss_listeners(out: &str) -> Vec<ListeningPort> {
    let mut seen = std::collections::BTreeSet::new();
    let mut list = Vec::new();
    for line in out.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }
        let addr = cols[3];
        let port = match addr.rsplit(':').next().and_then(|p| p.parse::<u16>().ok()) {
            Some(p) => p,
            None => continue,
        };
        // Noise filters: privileged/system ports and the ephemeral range
        // (vLLM workers etc. bind random ports there).
        if !(1024..32768).contains(&port) || KNOWN_INFRA.contains(&port) || !seen.insert(port) {
            continue;
        }
        let (process, pid) = cols
            .get(5)
            .map(|users| {
                let proc = users
                    .split('"')
                    .nth(1)
                    .filter(|p| !p.is_empty())
                    .map(|p| p.to_string());
                let pid = users
                    .split("pid=")
                    .nth(1)
                    .and_then(|r| r.split(',').next())
                    .and_then(|r| r.parse().ok());
                (proc, pid)
            })
            .unwrap_or((None, None));
        // Hide internal/agent/system processes; they are never useful links.
        let hidden = process.as_deref().is_some_and(|p| {
            let lp = p.to_lowercase();
            lp.contains("worker")
                || lp.contains("::")
                || matches!(
                    lp.as_str(),
                    "codex"
                        | "sshd"
                        | "systemd-resolved"
                        | "snapd"
                        | "systemd"
                        | "caddy"
                        | "easytier-core"
                        | "easytier-cli"
                )
        });
        if hidden {
            continue;
        }
        list.push(ListeningPort {
            port,
            addr: addr.to_string(),
            process,
            pid,
        });
    }
    list
}

async fn ports(State(st): State<AppState>) -> Json<Vec<ListeningPort>> {
    let out = tokio::task::spawn_blocking(|| {
        std::process::Command::new("ss")
            .args(["-tlnp"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default()
    })
    .await
    .unwrap_or_default();
    let list = parse_ss_listeners(&out);
    // Keep only ports that actually speak HTTP: send a minimal request and
    // require an "HTTP/" response. Raw RPC/queue listeners are dropped.
    let mut set = tokio::task::JoinSet::new();
    for item in list.iter().cloned() {
        set.spawn(async move { http_probe(item.port).await.then_some(item) });
    }
    let mut web: Vec<ListeningPort> = Vec::new();
    let mut probe_results = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok(Some(item)) = res {
            probe_results.push((item.port, true));
            web.push(item);
        }
    }
    // Every port we probed (web or not) records its liveness.
    let probed: Vec<u16> = list.iter().map(|p| p.port).collect();
    for port in probed {
        let up = probe_results.iter().any(|(p, _)| *p == port);
        probe_results.retain(|(p, _)| *p != port);
        st.health.write().unwrap().insert(port, up);
    }
    web.sort_by_key(|p| p.port);
    Json(web)
}

/// True when 127.0.0.1:port answers an HTTP/1.1 GET with an HTTP response.
async fn http_probe(port: u16) -> bool {
    let probe = async {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .ok()?;
        s.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .ok()?;
        let mut buf = [0u8; 8];
        let n = s.read(&mut buf).await.ok()?;
        if n >= 5 && &buf[..5] == b"HTTP/" {
            Some(())
        } else {
            None
        }
    };
    tokio::time::timeout(std::time::Duration::from_millis(1500), probe)
        .await
        .ok()
        .flatten()
        .is_some()
}

#[derive(Deserialize)]
struct PowerIn {
    /// "shutdown" | "reboot"
    action: String,
    /// must equal "confirm" — double-check against fat-finger taps
    confirm: String,
}

/// Accepts "confirm" robustly against mobile IME quirks (misclick guard, not
/// a security boundary; login is): normalizes full-width ASCII to half-width,
/// keeps only alphanumerics (drops spaces/zero-width/autocorrect dots),
/// lowercases everything.
fn normalize_confirm(word: &str) -> String {
    word.chars()
        .map(|c| match c {
            // Fullwidth ASCII variants (U+FF01..U+FF5E) -> ASCII.
            '\u{FF01}'..='\u{FF5E}' => char::from_u32(c as u32 - 0xFEE0).unwrap_or(c),
            _ => c,
        })
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase()
}

fn confirm_ok(word: &str) -> bool {
    normalize_confirm(word) == "confirm"
}

/// Power control for the host, gated behind login + typed confirmation.
/// Uses systemctl (not `poweroff`) so it works through systemd; the spawned
/// call is detached, the service will be stopped by the shutdown itself.
async fn power(State(st): State<AppState>, Json(input): Json<PowerIn>) -> Response {
    // Defense in depth: middleware already requires login for /api/*, but
    // power ops re-check the session cookie here as well.
    let _ = &st;
    // Case/space-insensitive: mobile keyboards often auto-capitalize.
    if !confirm_ok(&input.confirm) {
        // Log raw input so future mismatch reports can be diagnosed.
        eprintln!("power confirm mismatch, got: {:?}", input.confirm);
        return (StatusCode::BAD_REQUEST, "confirmation mismatch").into_response();
    }
    let unit = match input.action.as_str() {
        "shutdown" => "poweroff.target",
        "reboot" => "reboot.target",
        _ => return (StatusCode::BAD_REQUEST, "unknown action").into_response(),
    };
    // Minimal sudoers entry allows exactly these two systemctl commands.
    let child = match tokio::process::Command::new("sudo")
        .args(["-n", "systemctl", "start"])
        .arg(unit)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("spawn failed: {e}"),
            )
                .into_response()
        }
    };
    // systemctl start <target> returns quickly; shutdown proceeds async.
    // Collect stderr so failures are diagnosable from the response + log.
    let outcome = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output()).await;
    match outcome {
        Ok(Ok(out)) if out.status.success() => {
            (StatusCode::ACCEPTED, format!("{unit} requested")).into_response()
        }
        Ok(Ok(out)) => {
            let detail = String::from_utf8_lossy(&out.stderr).trim().to_string();
            eprintln!("power failed: exit {:?} stderr: {detail}", out.status);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("systemctl failed: {detail}"),
            )
                .into_response()
        }
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        // Timed out but likely still working; treat as accepted.
        Err(_) => (StatusCode::ACCEPTED, format!("{unit} requested")).into_response(),
    }
}

/// Minimal HTTP GET for same-host favicon probing: plain HTTP only, 2s budget.
async fn http_get_bytes(url: &str) -> Option<(Vec<u8>, String)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let rest = url.strip_prefix("http://")?;
    let hostport = rest.split('/').next().unwrap_or("");
    let mut stream = tokio::net::TcpStream::connect(hostport).await.ok()?;
    let path = if rest.len() > hostport.len() {
        &rest[hostport.len()..]
    } else {
        "/"
    };
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {hostport}\r\nUser-Agent: homepage-icon\r\nConnection: close\r\n\r\n"
    );
    let probe = async {
        stream.write_all(req.as_bytes()).await.ok()?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.ok()?;
        // Split headers/body tolerating both LF and CRLF.
        let sep = buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|i| (i, 4))
            .or_else(|| buf.windows(2).position(|w| w == b"\n\n").map(|i| (i, 2)))?;
        let head = String::from_utf8_lossy(&buf[..sep.0]).to_ascii_lowercase();
        let status_ok = head.as_str().get(9..12) == Some("200");
        if !status_ok {
            return None;
        }
        let ctype = head
            .lines()
            .find_map(|l| {
                l.strip_prefix("content-type:")
                    .map(|v| v.trim().to_string())
            })
            .unwrap_or_else(|| "application/octet-stream".into());
        Some((buf[sep.0 + sep.1..].to_vec(), ctype))
    };
    tokio::time::timeout(Duration::from_secs(2), probe)
        .await
        .ok()
        .flatten()
}

fn b64(data: &[u8]) -> String {
    // Tiny base64 (no external dep): standard alphabet with padding.
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18 & 63) as usize] as char);
        out.push(T[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[derive(Serialize)]
struct IconOut {
    /// "data:image/...;base64,..." ready for <img src>, or None.
    icon: Option<String>,
}

/// Best-effort favicon discovery for a local web service (magpie-style):
/// parse <link rel*=icon> from the page, fall back to /favicon.ico.
async fn icon_api(State(st): State<AppState>, AxPath(port): AxPath<u16>) -> Json<IconOut> {
    let _ = &st;
    let base = format!("http://127.0.0.1:{port}");
    let mut href: Option<String> = None;
    if let Some((body, _)) = http_get_bytes(&format!("{base}/")).await {
        let text = String::from_utf8_lossy(&body).to_ascii_lowercase();
        // crude scan: <link ... rel="...icon..." ... href="...">
        for seg in text.match_indices("<link") {
            let tail = &text[seg.0..text.len().min(seg.0 + 400)];
            let Some(end) = tail.find('>') else { continue };
            let tag = &tail[..end];
            let rel_ok = tag
                .split("rel=")
                .nth(1)
                .map(|r| {
                    r.trim_start_matches(['"', '\'']).starts_with("icon")
                        || r.trim_start_matches(['"', '\''])
                            .starts_with("shortcut icon")
                })
                .unwrap_or(false);
            if !rel_ok {
                continue;
            }
            if let Some(h) = tag.split("href=").nth(1) {
                let h = h.trim_start_matches(['"', '\'']);
                let h = h.split(['"', '\'']).next().unwrap_or("");
                href = Some(h.to_string());
                break;
            }
        }
    }
    // Resolve relative hrefs; only http(s) targets make sense here.
    let candidates: Vec<String> = match href {
        Some(h) if h.starts_with("data:image/") => {
            return Json(IconOut {
                icon: Some(h.to_string()),
            })
        }
        Some(h) if h.starts_with("http://") => vec![h],
        Some(h) if h.starts_with("https://") => vec![h],
        Some(h) if h.starts_with('/') => vec![format!("{base}{h}")],
        _ => vec![format!("{base}/favicon.ico"), format!("{base}/favicon.svg")],
    };
    for url in candidates {
        if let Some((bytes, ctype)) = http_get_bytes(&url).await {
            if !bytes.is_empty() && bytes.len() < 512 * 1024 && ctype.starts_with("image/") {
                return Json(IconOut {
                    icon: Some(format!("data:{ctype};base64,{}", b64(&bytes))),
                });
            }
        }
        // Fallbacks already enumerated; no further probing.
    }
    Json(IconOut { icon: None })
}

async fn page() -> Html<&'static str> {
    Html(include_str!("index.html"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let data =
        std::env::var("HOME_DATA").unwrap_or_else(|_| "/var/lib/homepage/services.json".into());
    let addr = std::env::var("HOME_ADDR").unwrap_or_else(|_| "127.0.0.1:8090".into());
    let path = PathBuf::from(&data);
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).ok();
    }
    let services = fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    // Session token persisted so logins survive restarts.
    let key_path = path.with_file_name("session.key");
    let token = fs::read_to_string(&key_path)
        .ok()
        .filter(|t| t.len() >= 16)
        .map(|t| t.trim().to_string())
        .unwrap_or_else(|| {
            let mut bytes = [0u8; 24];
            if let Ok(mut f) = fs::File::open("/dev/urandom") {
                use std::io::Read as _;
                let _ = f.read(&mut bytes);
            }
            let t = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
            if let Err(e) = write_secret(&key_path, &t) {
                eprintln!("warning: could not persist session key: {e}");
            }
            t
        });
    let password = std::env::var("HOME_PASSWORD")
        .ok()
        .filter(|p| !p.is_empty());
    let user = std::env::var("HOME_USER").unwrap_or_else(|_| "admin".to_string());
    if password.is_none() {
        eprintln!("warning: HOME_PASSWORD not set, authentication is DISABLED");
    }
    let state = AppState {
        services: Arc::new(RwLock::new(services)),
        path,
        attempts: Arc::new(Mutex::new(std::collections::HashMap::new())),
        health: Arc::new(RwLock::new(std::collections::HashMap::new())),
        token,
        password,
        user,
    };

    // Periodic liveness refresh for listed services (every 30s).
    {
        let st = state.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                let services = st.services.read().unwrap().clone();
                let ports: Vec<u16> = services
                    .iter()
                    .filter_map(|s| service_port(&s.url))
                    .collect();
                let mut set = tokio::task::JoinSet::new();
                for p in ports {
                    set.spawn(async move { (p, http_probe(p).await) });
                }
                while let Some(Ok((port, up))) = set.join_next().await {
                    st.health.write().unwrap().insert(port, up);
                }
            }
        });
    }

    let app = Router::new()
        .route("/", get(page))
        .route("/login", get(login_page))
        .route("/api/login", post(login))
        .route("/api/services", get(list).post(add))
        .route("/api/services/{id}", put(update).delete(remove))
        .route("/api/ports", get(ports))
        .route("/api/icon/{port}", get(icon_api))
        .route("/api/power", post(power))
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    eprintln!("homepage listening on http://{addr}");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SS_FIXTURE: &str = "State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess\n\
LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:* users((\"gpu-monitor\",pid=100,fd=19))\n\
LISTEN 0 4096 127.0.0.1:53 0.0.0.0:*\n\
LISTEN 0 4096 0.0.0.0:15888 0.0.0.0:*\n\
LISTEN 0 1024 0.0.0.0:40000 0.0.0.0:* users((\"VLLM::Worker_PP\",pid=2,fd=1))\n\
LISTEN 0 4096 0.0.0.0:3080 0.0.0.0:* users((\"codeg-server\",pid=7,fd=24))\n\
LISTEN 0 4096 0.0.0.0:3080 0.0.0.0:* users((\"codeg-server\",pid=7,fd=25))\n\
LISTEN 0 4096 [::]:22 [::]:* users((\"sshd\",pid=1,fd=3))\n";

    #[test]
    fn parse_ss_filters_noise_and_dedups() {
        let list = parse_ss_listeners(SS_FIXTURE);
        let ports: Vec<u16> = list.iter().map(|p| p.port).collect();
        // 8080 + 3080 kept; 53(<1024), 15888(infra), 40000(ephemeral+worker), 22(sshd) gone; dup 3080 collapsed.
        assert_eq!(ports, vec![8080, 3080]);
        assert_eq!(list[0].process.as_deref(), Some("gpu-monitor"));
        assert_eq!(list[0].pid, Some(100));
    }

    #[test]
    fn service_port_parsing() {
        assert_eq!(service_port("8080"), Some(8080));
        assert_eq!(service_port("5200/docs"), Some(5200));
        assert_eq!(service_port("http://host:9000/x"), Some(9000));
        assert_eq!(service_port("https://example.com"), None);
        assert_eq!(service_port("/local-path"), None);
    }

    #[test]
    fn confirm_word_check() {
        assert!(confirm_ok("confirm"));
        assert!(confirm_ok("Confirm")); // mobile autocapitalize
        assert!(confirm_ok("  CONFIRM "));
        assert!(confirm_ok("ｃｏｎｆｉｒｍ")); // fullwidth IME input
        assert!(confirm_ok("Ｃｏｎｆｉｒｍ")); // fullwidth + capitalize
        assert!(confirm_ok("confirm.")); // autocorrect trailing dot
        assert!(confirm_ok("c​onfirm")); // zero-width char
        assert!(!confirm_ok("no"));
        assert!(!confirm_ok(""));
        assert!(!confirm_ok("コｎｆｉｒｍx"));
    }

    #[test]
    fn password_check() {
        assert!(check_password("abc123", "abc123"));
        assert!(!check_password("abc124", "abc123"));
        assert!(!check_password("abc", "abc123"));
    }
}
