//! HTTP API for the RustVPN admin UI.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Extension, Path as AxumPath, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{Datelike, TimeZone, Utc};
use futures_util::StreamExt;
use rust_embed::RustEmbed;
use rustvpn_crypto::verifier::Verifier;
use rustvpn_net::config::PeerYaml;
use rustvpn_proto::MTU_DEFAULT;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use subtle::ConstantTimeEq;
use tokio_stream::wrappers::IntervalStream;

use crate::auth::{self, AuthUser};
use crate::config_edit;
use crate::model::{
    id_hex, mode_name, now_unix, parse_id, peer_id_of, rfc3339, ApplyReport, ApplyRequest,
    ConfigError, ConfigFiles, ConfigSnapshot, KickReport, PeerDetail, PeerId, PeerList, PeerView,
    PreviewReport, SessionInfo, Summary, TrafficTotals,
};
use crate::state::AdminState;

#[derive(RustEmbed)]
#[folder = "ui/"]
struct Assets;

#[derive(Clone, Debug)]
struct AuthContext {
    user: AuthUser,
    csrf: String,
}

pub fn router(state: Arc<AdminState>) -> Router {
    let protected = Router::new()
        .route("/api/me", get(me))
        .route("/api/me/password", post(change_password))
        .route("/api/logout", post(logout))
        .route("/api/peers", get(list_peers).post(create_peer))
        .route(
            "/api/peers/{id}",
            get(get_peer).patch(update_peer).delete(delete_peer),
        )
        .route("/api/peers/{id}/disable", post(disable_peer))
        .route("/api/peers/{id}/enable", post(enable_peer))
        .route("/api/peers/{id}/rotate", post(rotate_peer))
        .route("/api/peers/{id}/kick", post(kick_peer))
        .route("/api/peers/{id}/traffic", get(peer_traffic))
        .route("/api/peers/{id}/sessions", get(peer_sessions))
        .route("/api/sessions", get(list_sessions))
        .route("/api/system/status", get(system_status))
        .route("/api/system/events", get(system_events))
        .route("/api/system/config", get(get_config).put(apply_config))
        .route("/api/system/config/preview", post(preview_config))
        .route("/api/system/backups", get(list_backups))
        .route("/api/system/backups/restore", post(restore_backup))
        .route("/api/audit", get(list_audit))
        .route("/api/events", get(sse_events))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth_mw));

    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/app.css", get(app_css))
        .route("/favicon.svg", get(favicon))
        .route("/api/login", post(login))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .merge(protected)
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

// ---- middleware ---------------------------------------------------------

async fn security_headers(req: Request, next: Next) -> Response {
    let secure = req.uri().path().starts_with("/api");
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert(
        axum::http::HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
             img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; \
             base-uri 'none'; form-action 'self'",
        ),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if secure { "no-store" } else { "no-cache" }),
    );
    response
}

async fn auth_mw(State(state): State<Arc<AdminState>>, mut req: Request, next: Next) -> Response {
    let name = cookie_name(state.options.secure_cookies);
    let Some(token) = cookie_value(req.headers(), name) else {
        return ApiError::unauthorized();
    };
    let Some((user, csrf)) = state.auth.lookup(&token) else {
        return ApiError::unauthorized();
    };
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let mutating = method != Method::GET && method != Method::HEAD;
    if mutating {
        let supplied = req
            .headers()
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !constant_eq(supplied, &csrf) {
            return ApiError::new(StatusCode::FORBIDDEN, "csrf", "invalid CSRF token")
                .into_response();
        }
        let allowed_for_viewer = path == "/api/logout" || path == "/api/me/password";
        if !user.is_admin() && !allowed_for_viewer {
            return ApiError::new(StatusCode::FORBIDDEN, "forbidden", "admin role required")
                .into_response();
        }
    }
    req.extensions_mut().insert(AuthContext { user, csrf });
    next.run(req).await
}

fn constant_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.as_bytes().ct_eq(b.as_bytes()).unwrap_u8() == 1
}

// ---- errors -------------------------------------------------------------

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    extra: Option<Value>,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            extra: None,
        }
    }

    fn unauthorized() -> Response {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", "login required").into_response()
    }

    fn bad(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = json!({ "error": self.message, "code": self.code });
        if let Some(extra) = self.extra {
            if let Some(object) = body.as_object_mut() {
                if let Some(extra) = extra.as_object() {
                    object.extend(extra.clone());
                }
            }
        }
        (self.status, Json(body)).into_response()
    }
}

impl From<ConfigError> for ApiError {
    fn from(error: ConfigError) -> Self {
        match error {
            ConfigError::Conflict { current_etag } => {
                let mut api = ApiError::conflict(format!(
                    "configuration changed on disk (current etag {current_etag})"
                ));
                api.extra = Some(json!({ "current_etag": current_etag }));
                api
            }
            ConfigError::Invalid(message) => ApiError::bad(message),
            ConfigError::Io(message) => {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "io", message)
            }
        }
    }
}

impl From<String> for ApiError {
    fn from(message: String) -> Self {
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", message)
    }
}

// ---- static assets ------------------------------------------------------

fn asset(path: &str) -> Response {
    match Assets::get(path) {
        Some(content) => {
            let mime = match path.rsplit('.').next().unwrap_or("") {
                "html" => "text/html; charset=utf-8",
                "js" => "text/javascript; charset=utf-8",
                "css" => "text/css; charset=utf-8",
                "svg" => "image/svg+xml",
                "png" => "image/png",
                "ico" => "image/x-icon",
                _ => "application/octet-stream",
            };
            let mut response = (
                [(header::CONTENT_TYPE, HeaderValue::from_static(mime))],
                content.data.into_owned(),
            )
                .into_response();
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
            response
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

async fn index() -> Response {
    asset("index.html")
}
async fn app_js() -> Response {
    asset("app.js")
}
async fn app_css() -> Response {
    asset("app.css")
}
async fn favicon() -> Response {
    asset("favicon.svg")
}

async fn healthz() -> &'static str {
    "ok"
}

async fn readyz(State(state): State<Arc<AdminState>>) -> Response {
    match state.backend.config_snapshot().await {
        Ok(_) => (StatusCode::OK, "ready").into_response(),
        Err(error) => (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response(),
    }
}

// ---- authentication -----------------------------------------------------

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

async fn login(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> Response {
    let ip = client_ip(&headers);
    let user_key = format!("user:{}", request.username);
    let ip_key = format!("ip:{ip}");
    if !state.limiter.allow(&user_key) || !state.limiter.allow(&ip_key) {
        let _ = state
            .audit(
                &request.username,
                &ip,
                "login",
                &request.username,
                json!({"reason": "rate_limited"}),
                "denied",
            )
            .await;
        return ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many login attempts",
        )
        .into_response();
    }

    let username = request.username.clone();
    let record = state.db(move |store| store.get_admin(&username)).await;
    let record = match record {
        Ok(Some(record)) => record,
        Ok(None) => {
            state.limiter.failure(&user_key);
            state.limiter.failure(&ip_key);
            let _ = state
                .audit(
                    &request.username,
                    &ip,
                    "login",
                    &request.username,
                    json!({"reason": "invalid_credentials"}),
                    "denied",
                )
                .await;
            return ApiError::new(
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                "invalid username or password",
            )
            .into_response();
        }
        Err(error) => {
            return ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", error)
                .into_response()
        }
    };

    let password = request.password.clone();
    let record_for_verify = record.clone();
    let verified = tokio::task::spawn_blocking(move || {
        auth::verify_password(
            &password,
            &record_for_verify.salt,
            &record_for_verify.hash,
            record_for_verify.m,
            record_for_verify.t,
            record_for_verify.p,
        )
    })
    .await
    .unwrap_or(false);

    if !verified {
        state.limiter.failure(&user_key);
        state.limiter.failure(&ip_key);
        let _ = state
            .audit(
                &request.username,
                &ip,
                "login",
                &request.username,
                json!({"reason": "invalid_credentials"}),
                "denied",
            )
            .await;
        return ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "invalid username or password",
        )
        .into_response();
    }

    state.limiter.success(&user_key);
    state.limiter.success(&ip_key);
    let (token, csrf) = state.auth.create_session(&record.username, &record.role);
    if token.is_empty() || csrf.is_empty() {
        return ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "random source failed",
        )
        .into_response();
    }
    let _ = state
        .audit(
            &record.username,
            &ip,
            "login",
            &record.username,
            json!({"role": record.role}),
            "ok",
        )
        .await;

    let cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200{}",
        cookie_name(state.options.secure_cookies),
        token,
        if state.options.secure_cookies {
            "; Secure"
        } else {
            ""
        }
    );
    let mut response = Json(json!({
        "user": record.username,
        "role": record.role,
        "csrf_token": csrf,
    }))
    .into_response();
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

async fn me(Extension(ctx): Extension<AuthContext>) -> Json<Value> {
    Json(json!({
        "user": ctx.user.username,
        "role": ctx.user.role,
        "csrf_token": ctx.csrf,
    }))
}

async fn logout(
    State(state): State<Arc<AdminState>>,
    Extension(ctx): Extension<AuthContext>,
    headers: HeaderMap,
) -> Response {
    if let Some(token) = cookie_value(&headers, cookie_name(state.options.secure_cookies)) {
        state.auth.remove(&token);
    }
    let _ = state
        .audit(
            &ctx.user.username,
            &client_ip(&headers),
            "logout",
            &ctx.user.username,
            json!({}),
            "ok",
        )
        .await;
    let cookie = format!(
        "{}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{}",
        cookie_name(state.options.secure_cookies),
        if state.options.secure_cookies {
            "; Secure"
        } else {
            ""
        }
    );
    let mut response = Json(json!({"ok": true})).into_response();
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

#[derive(Deserialize)]
struct PasswordRequest {
    current_password: String,
    new_password: String,
}

async fn change_password(
    State(state): State<Arc<AdminState>>,
    Extension(ctx): Extension<AuthContext>,
    headers: HeaderMap,
    Json(request): Json<PasswordRequest>,
) -> Result<Json<Value>, ApiError> {
    if request.new_password.len() < 12 {
        return Err(ApiError::bad("new password must be at least 12 characters"));
    }
    let username = ctx.user.username.clone();
    let record = state
        .db(move |store| store.get_admin(&username))
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized", "login required"))?;
    let current = request.current_password.clone();
    let record_for_verify = record.clone();
    let verified = tokio::task::spawn_blocking(move || {
        auth::verify_password(
            &current,
            &record_for_verify.salt,
            &record_for_verify.hash,
            record_for_verify.m,
            record_for_verify.t,
            record_for_verify.p,
        )
    })
    .await
    .unwrap_or(false);
    if !verified {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "invalid_credentials",
            "current password is incorrect",
        ));
    }
    let new_password = request.new_password;
    let (salt, hash) = tokio::task::spawn_blocking(move || {
        auth::hash_password(
            &new_password,
            auth::DEFAULT_M,
            auth::DEFAULT_T,
            auth::DEFAULT_P,
        )
    })
    .await
    .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string()))?
    .map_err(ApiError::bad)?;
    let username = ctx.user.username.clone();
    let role = ctx.user.role.clone();
    state
        .db(move |store| {
            store.upsert_admin(
                &username,
                &role,
                &salt,
                &hash,
                auth::DEFAULT_M,
                auth::DEFAULT_T,
                auth::DEFAULT_P,
            )
        })
        .await?;
    state.auth.remove_user_sessions(&ctx.user.username);
    state
        .audit(
            &ctx.user.username,
            &client_ip(&headers),
            "admin.password",
            &ctx.user.username,
            json!({}),
            "ok",
        )
        .await;
    Ok(Json(json!({"ok": true, "relogin": true})))
}

// ---- peers --------------------------------------------------------------

async fn list_peers(State(state): State<Arc<AdminState>>) -> Result<Json<PeerList>, ApiError> {
    let snapshot = state.backend.config_snapshot().await?;
    let sessions = state.sessions_with_rates().await;
    let meta = state.db(|store| store.all_peer_meta()).await?;
    let lifetimes = state.db(|store| store.lifetime_all()).await?;
    let month = month_start();
    let usage = state.db(move |store| store.month_usage_all(month)).await?;
    let today = day_start();
    let (today_in, today_out) = state.db(move |store| store.total_usage_all(today)).await?;

    let peers = build_peer_views(&snapshot, &sessions, &meta, &lifetimes, &usage);
    let summary = Summary {
        configured: snapshot.files.enabled.len(),
        disabled: snapshot.files.disabled.len(),
        online: sessions.len(),
        rate_in_bps: sessions.iter().map(|s| s.rate_in_bps).sum(),
        rate_out_bps: sessions.iter().map(|s| s.rate_out_bps).sum(),
        today_payload_in: today_in,
        today_payload_out: today_out,
    };
    Ok(Json(PeerList { summary, peers }))
}

async fn get_peer(
    State(state): State<Arc<AdminState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<PeerDetail>, ApiError> {
    let id = parse_id(&id).map_err(ApiError::bad)?;
    let snapshot = state.backend.config_snapshot().await?;
    let Some((_name, peer, _enabled)) = config_edit::find_peer(&snapshot.files, &id) else {
        return Err(ApiError::not_found("peer not found"));
    };
    let sessions = state.sessions_with_rates().await;
    let meta = state.db(|store| store.all_peer_meta()).await?;
    let lifetime = state.db(move |store| store.lifetime(&id)).await?;
    let month = month_start();
    let usage = state.db(move |store| store.month_usage_all(month)).await?;
    let views = build_peer_views(&snapshot, &sessions, &meta, &HashMap::new(), &usage);
    let view = views
        .into_iter()
        .find(|view| view.id == id_hex(&id))
        .ok_or_else(|| ApiError::not_found("peer not found"))?;
    // Session rows (including the active one) are refreshed by the sampler,
    // so the stored lifetime already includes current traffic.
    Ok(Json(PeerDetail {
        view: PeerView { lifetime, ..view },
        up: peer.up.clone(),
        down: peer.down.clone(),
        timeout: peer.timeout,
        noise: peer.noise,
        encless: peer.encless,
        cpr: peer.cpr,
        timesync: peer.timesync,
        verifier_id: id_hex(&id),
    }))
}

#[derive(Deserialize)]
struct CreatePeerRequest {
    name: String,
    #[serde(default)]
    iface: String,
    #[serde(default)]
    mtu: Option<usize>,
    #[serde(default)]
    timeout: Option<i64>,
    #[serde(default)]
    noise: bool,
    #[serde(default)]
    encless: bool,
    #[serde(default)]
    cpr: u32,
    #[serde(default)]
    timesync: i64,
    #[serde(default)]
    up: String,
    #[serde(default)]
    down: String,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    quota_bytes_month: Option<u64>,
    #[serde(default)]
    generate_password: bool,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    import_long_verifier: Option<String>,
}

#[derive(Serialize)]
struct CredentialResponse {
    id: String,
    name: String,
    password: Option<String>,
    short_verifier: String,
    client_env: String,
    client_command: String,
}

async fn create_peer(
    State(state): State<Arc<AdminState>>,
    Extension(ctx): Extension<AuthContext>,
    headers: HeaderMap,
    Json(request): Json<CreatePeerRequest>,
) -> Result<Json<CredentialResponse>, ApiError> {
    config_edit::validate_peer_name(&request.name)?;
    let mut snapshot = state.backend.config_snapshot().await?;
    if snapshot.files.enabled.contains_key(&request.name)
        || snapshot.files.disabled.contains_key(&request.name)
    {
        return Err(ApiError::conflict("peer name already exists"));
    }
    if request.import_long_verifier.is_some() && request.password.is_some() {
        return Err(ApiError::bad(
            "choose either import_long_verifier or password",
        ));
    }

    let encless = request.encless;
    let noise = request.noise || encless;
    let mut peer = PeerYaml {
        iface: request.iface,
        mtu: request.mtu.unwrap_or(MTU_DEFAULT),
        up: request.up,
        down: request.down,
        timeout: request.timeout.unwrap_or(60),
        noise,
        cpr: request.cpr,
        encless,
        timesync: request.timesync,
        verifier: String::new(),
    };

    let (password, generated) = if let Some(raw) = request.import_long_verifier {
        let verifier = Verifier::from_string(&raw).map_err(|e| ApiError::bad(e.to_string()))?;
        if verifier.public.is_none() {
            return Err(ApiError::bad("imported verifier must be in long form"));
        }
        peer.verifier = raw;
        (None, false)
    } else {
        if request.password.is_none() && !request.generate_password {
            return Err(ApiError::bad(
                "provide a password, set generate_password, or import a long verifier",
            ));
        }
        let password = match request.password {
            Some(password) => {
                if password.len() < 12 {
                    return Err(ApiError::bad("password must be at least 12 characters"));
                }
                password
            }
            None => generated_password()?,
        };
        let derived = derive_verifier(&password, None).await?;
        peer.verifier = derived;
        (Some(password), request.generate_password)
    };

    config_edit::validate_peer_settings(&request.name, &peer)?;
    config_edit::validate_script_allowlist(&request.name, &peer, &state.options.script_dirs)?;

    let id = peer_id_of(&peer).ok_or_else(|| ApiError::bad("invalid verifier"))?;
    for existing in snapshot
        .files
        .enabled
        .values()
        .chain(snapshot.files.disabled.values())
    {
        if peer_id_of(existing) == Some(id) {
            return Err(ApiError::conflict("peer identity already exists"));
        }
    }

    snapshot
        .files
        .enabled
        .insert(request.name.clone(), peer.clone());
    let (enabled_yaml, disabled_yaml) = snapshot.files.render()?;
    let report = state
        .backend
        .apply_config(ApplyRequest {
            enabled_yaml,
            disabled_yaml,
            expected_etag: snapshot.etag.clone(),
            comment: format!("create peer {}", request.name),
        })
        .await?;

    let id_bytes = id;
    let name = request.name.clone();
    let notes = request.notes.clone();
    let quota = request.quota_bytes_month.filter(|quota| *quota > 0);
    state
        .db(move |store| store.upsert_peer_meta(&id_bytes, &name, notes.as_deref(), quota))
        .await?;

    state
        .audit(
            &ctx.user.username,
            &client_ip(&headers),
            "peer.create",
            &request.name,
            json!({
                "iface": peer.iface,
                "mode": mode_name(peer.noise, peer.encless),
                "backups": report.backups,
            }),
            "ok",
        )
        .await;

    let verifier =
        Verifier::from_string(&peer.verifier).map_err(|e| ApiError::bad(e.to_string()))?;
    let short_verifier = verifier.short_form();
    Ok(Json(CredentialResponse {
        id: id_hex(&id),
        name: request.name.clone(),
        password: if generated { password } else { None },
        client_env: format!("RUSTVPN_VERIFIER='{short_verifier}'\n"),
        client_command: client_command(&request.name, &peer, &short_verifier),
        short_verifier,
    }))
}

#[derive(Deserialize)]
struct UpdatePeerRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    iface: Option<String>,
    #[serde(default)]
    mtu: Option<usize>,
    #[serde(default)]
    timeout: Option<i64>,
    #[serde(default)]
    noise: Option<bool>,
    #[serde(default)]
    encless: Option<bool>,
    #[serde(default)]
    cpr: Option<u32>,
    #[serde(default)]
    timesync: Option<i64>,
    #[serde(default)]
    up: Option<String>,
    #[serde(default)]
    down: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    quota_bytes_month: Option<u64>,
    #[serde(default)]
    clear_quota: bool,
}

async fn update_peer(
    State(state): State<Arc<AdminState>>,
    Extension(ctx): Extension<AuthContext>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<UpdatePeerRequest>,
) -> Result<Json<Value>, ApiError> {
    let id = parse_id(&id).map_err(ApiError::bad)?;
    let mut snapshot = state.backend.config_snapshot().await?;
    let Some((old_name, old_peer, enabled)) = config_edit::find_peer(&snapshot.files, &id) else {
        return Err(ApiError::not_found("peer not found"));
    };
    let old_name = old_name.to_string();
    let mut peer = old_peer.clone();
    if let Some(value) = request.iface {
        peer.iface = value;
    }
    if let Some(value) = request.mtu {
        peer.mtu = value;
    }
    if let Some(value) = request.timeout {
        peer.timeout = value;
    }
    if let Some(value) = request.noise {
        peer.noise = value;
    }
    if let Some(value) = request.encless {
        peer.encless = value;
        if value {
            peer.noise = true;
        }
    }
    if let Some(value) = request.cpr {
        peer.cpr = value;
    }
    if let Some(value) = request.timesync {
        peer.timesync = value;
    }
    if let Some(value) = request.up {
        peer.up = value;
    }
    if let Some(value) = request.down {
        peer.down = value;
    }
    let new_name = request.name.unwrap_or_else(|| old_name.clone());
    config_edit::validate_peer_name(&new_name)?;
    config_edit::validate_peer_settings(&new_name, &peer)?;
    config_edit::validate_script_allowlist(&new_name, &peer, &state.options.script_dirs)?;
    if new_name != old_name
        && (snapshot.files.enabled.contains_key(&new_name)
            || snapshot.files.disabled.contains_key(&new_name))
    {
        return Err(ApiError::conflict("peer name already exists"));
    }

    let settings_changed = peer != *old_peer || new_name != old_name;
    if settings_changed {
        let map = if enabled {
            &mut snapshot.files.enabled
        } else {
            &mut snapshot.files.disabled
        };
        map.remove(&old_name);
        map.insert(new_name.clone(), peer.clone());
        let (enabled_yaml, disabled_yaml) = snapshot.files.render()?;
        state
            .backend
            .apply_config(ApplyRequest {
                enabled_yaml,
                disabled_yaml,
                expected_etag: snapshot.etag.clone(),
                comment: format!("update peer {old_name}"),
            })
            .await?;
    }

    let notes = request.notes.map(|notes| {
        if notes.trim().is_empty() {
            None
        } else {
            Some(notes)
        }
    });
    let quota = if request.clear_quota {
        Some(None)
    } else {
        request
            .quota_bytes_month
            .map(|quota| if quota == 0 { None } else { Some(quota) })
    };
    if notes.is_some() || quota.is_some() {
        let existing = state.db(move |store| store.all_peer_meta()).await?;
        let meta = existing.get(&id);
        let notes_value = match notes {
            Some(value) => value,
            None => meta.and_then(|m| m.notes.clone()),
        };
        let quota_value = match quota {
            Some(value) => value,
            None => meta.and_then(|m| m.quota_bytes_month),
        };
        let notes_for_db = notes_value.clone();
        state
            .db(move |store| store.set_peer_meta(&id, notes_for_db.as_deref(), quota_value))
            .await?;
    }

    state
        .audit(
            &ctx.user.username,
            &client_ip(&headers),
            "peer.update",
            &new_name,
            json!({"old_name": old_name, "config_applied": settings_changed}),
            "ok",
        )
        .await;
    Ok(Json(json!({
        "updated": true,
        "config_applied": settings_changed,
        "name": new_name,
        "id": id_hex(&id),
    })))
}

async fn delete_peer(
    State(state): State<Arc<AdminState>>,
    Extension(ctx): Extension<AuthContext>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Query(query): Query<DeleteQuery>,
) -> Result<Json<Value>, ApiError> {
    let id = parse_id(&id).map_err(ApiError::bad)?;
    let mut snapshot = state.backend.config_snapshot().await?;
    let Some((name, _peer, enabled)) = config_edit::find_peer(&snapshot.files, &id) else {
        return Err(ApiError::not_found("peer not found"));
    };
    let name = name.to_string();
    if enabled {
        snapshot.files.enabled.remove(&name);
    } else {
        snapshot.files.disabled.remove(&name);
    }
    let (enabled_yaml, disabled_yaml) = snapshot.files.render()?;
    state
        .backend
        .apply_config(ApplyRequest {
            enabled_yaml,
            disabled_yaml,
            expected_etag: snapshot.etag.clone(),
            comment: format!("delete peer {name}"),
        })
        .await?;
    if query.purge_history {
        state.db(move |store| store.purge_peer(&id)).await?;
    }
    state
        .audit(
            &ctx.user.username,
            &client_ip(&headers),
            "peer.delete",
            &name,
            json!({"purge_history": query.purge_history}),
            "ok",
        )
        .await;
    Ok(Json(json!({"deleted": true, "name": name})))
}

#[derive(Deserialize, Default)]
struct DeleteQuery {
    #[serde(default)]
    purge_history: bool,
}

async fn disable_peer(
    State(state): State<Arc<AdminState>>,
    Extension(ctx): Extension<AuthContext>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    move_peer(state, ctx, headers, id, false).await
}

async fn enable_peer(
    State(state): State<Arc<AdminState>>,
    Extension(ctx): Extension<AuthContext>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    move_peer(state, ctx, headers, id, true).await
}

async fn move_peer(
    state: Arc<AdminState>,
    ctx: AuthContext,
    headers: HeaderMap,
    id: String,
    enable: bool,
) -> Result<Json<Value>, ApiError> {
    let id = parse_id(&id).map_err(ApiError::bad)?;
    let mut snapshot = state.backend.config_snapshot().await?;
    let Some((name, peer, already_enabled)) = config_edit::find_peer(&snapshot.files, &id) else {
        return Err(ApiError::not_found("peer not found"));
    };
    if already_enabled == enable {
        return Ok(Json(json!({
            "changed": false,
            "enabled": enable,
            "name": name,
        })));
    }
    let name = name.to_string();
    let peer = peer.clone();
    snapshot.files.enabled.remove(&name);
    snapshot.files.disabled.remove(&name);
    if enable {
        snapshot.files.enabled.insert(name.clone(), peer);
    } else {
        snapshot.files.disabled.insert(name.clone(), peer);
    }
    let (enabled_yaml, disabled_yaml) = snapshot.files.render()?;
    state
        .backend
        .apply_config(ApplyRequest {
            enabled_yaml,
            disabled_yaml,
            expected_etag: snapshot.etag.clone(),
            comment: format!("{} peer {name}", if enable { "enable" } else { "disable" }),
        })
        .await?;
    state
        .audit(
            &ctx.user.username,
            &client_ip(&headers),
            if enable {
                "peer.enable"
            } else {
                "peer.disable"
            },
            &name,
            json!({}),
            "ok",
        )
        .await;
    Ok(Json(
        json!({"changed": true, "enabled": enable, "name": name}),
    ))
}

#[derive(Deserialize)]
struct RotateRequest {
    #[serde(default)]
    generate_password: bool,
    #[serde(default)]
    password: Option<String>,
}

async fn rotate_peer(
    State(state): State<Arc<AdminState>>,
    Extension(ctx): Extension<AuthContext>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<RotateRequest>,
) -> Result<Json<CredentialResponse>, ApiError> {
    let id = parse_id(&id).map_err(ApiError::bad)?;
    let mut snapshot = state.backend.config_snapshot().await?;
    let Some((name, peer, enabled)) = config_edit::find_peer(&snapshot.files, &id) else {
        return Err(ApiError::not_found("peer not found"));
    };
    let name = name.to_string();
    let mut peer = peer.clone();
    let old = Verifier::from_string(&peer.verifier).map_err(|e| ApiError::bad(e.to_string()))?;
    if request.password.is_none() && !request.generate_password {
        return Err(ApiError::bad("provide a password or set generate_password"));
    }
    let password = match request.password {
        Some(password) => {
            if password.len() < 12 {
                return Err(ApiError::bad("password must be at least 12 characters"));
            }
            password
        }
        None => generated_password()?,
    };
    let new_verifier = derive_verifier(&password, Some(old)).await?;
    peer.verifier = new_verifier;
    let map = if enabled {
        &mut snapshot.files.enabled
    } else {
        &mut snapshot.files.disabled
    };
    map.insert(name.clone(), peer.clone());
    let (enabled_yaml, disabled_yaml) = snapshot.files.render()?;
    state
        .backend
        .apply_config(ApplyRequest {
            enabled_yaml,
            disabled_yaml,
            expected_etag: snapshot.etag.clone(),
            comment: format!("rotate credentials for {name}"),
        })
        .await?;
    state
        .audit(
            &ctx.user.username,
            &client_ip(&headers),
            "peer.rotate",
            &name,
            json!({}),
            "ok",
        )
        .await;
    let verifier =
        Verifier::from_string(&peer.verifier).map_err(|e| ApiError::bad(e.to_string()))?;
    let short_verifier = verifier.short_form();
    Ok(Json(CredentialResponse {
        id: id_hex(&id),
        name: name.clone(),
        password: Some(password),
        client_env: format!("RUSTVPN_VERIFIER='{short_verifier}'\n"),
        client_command: client_command(&name, &peer, &short_verifier),
        short_verifier,
    }))
}

async fn derive_verifier(password: &str, existing: Option<Verifier>) -> Result<String, ApiError> {
    let password = password.to_string();
    tokio::task::spawn_blocking(move || -> Result<String, String> {
        let id = match existing {
            Some(mut verifier) => {
                verifier.public = None;
                verifier
                    .password_apply(&password)
                    .map_err(|e| e.to_string())?;
                verifier.long_form().map_err(|e| e.to_string())?
            }
            None => {
                let mut id = [0u8; 16];
                getrandom::getrandom(&mut id).map_err(|e| e.to_string())?;
                let mut verifier =
                    Verifier::new(auth::DEFAULT_M, auth::DEFAULT_T, auth::DEFAULT_P, id);
                verifier
                    .password_apply(&password)
                    .map_err(|e| e.to_string())?;
                verifier.long_form().map_err(|e| e.to_string())?
            }
        };
        Ok(id)
    })
    .await
    .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string()))?
    .map_err(ApiError::bad)
}

#[derive(Deserialize)]
struct KickRequest {
    #[serde(default)]
    reason: String,
}

async fn kick_peer(
    State(state): State<Arc<AdminState>>,
    Extension(ctx): Extension<AuthContext>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<KickRequest>,
) -> Result<Json<KickReport>, ApiError> {
    let id = parse_id(&id).map_err(ApiError::bad)?;
    let reason = if request.reason.trim().is_empty() {
        "admin_kick".to_string()
    } else {
        request.reason
    };
    let report = state
        .backend
        .kick(id, reason.clone())
        .await
        .map_err(ApiError::conflict)?;
    state
        .audit(
            &ctx.user.username,
            &client_ip(&headers),
            "peer.kick",
            &id_hex(&id),
            json!({"reason": reason}),
            "ok",
        )
        .await;
    Ok(Json(report))
}

#[derive(Deserialize)]
struct TrafficQuery {
    #[serde(default)]
    range: Option<String>,
    #[serde(default)]
    from: Option<i64>,
    #[serde(default)]
    to: Option<i64>,
    #[serde(default)]
    step: Option<i64>,
    #[serde(default)]
    hourly: Option<bool>,
}

async fn peer_traffic(
    State(state): State<Arc<AdminState>>,
    AxumPath(id): AxumPath<String>,
    Query(query): Query<TrafficQuery>,
) -> Result<Json<Value>, ApiError> {
    let id = parse_id(&id).map_err(ApiError::bad)?;
    let now = now_unix();
    let range = query.range.unwrap_or_else(|| "24h".to_string());
    let (from, to, step, hourly) = match range.as_str() {
        "1h" => (now - 3_600, now, 60, false),
        "24h" => (now - 86_400, now, 300, false),
        "7d" => (now - 7 * 86_400, now, 3_600, false),
        "30d" => (now - 30 * 86_400, now, 3_600, true),
        "custom" => (
            query
                .from
                .ok_or_else(|| ApiError::bad("from is required"))?,
            query.to.unwrap_or(now),
            query.step.unwrap_or(60),
            query.hourly.unwrap_or(false),
        ),
        other => return Err(ApiError::bad(format!("unknown range {other:?}"))),
    };
    if step <= 0 {
        return Err(ApiError::bad("step must be positive"));
    }
    let points = state
        .db(move |store| store.traffic_series(&id, from, to, step, hourly))
        .await?;
    let totals = points
        .iter()
        .fold(TrafficTotals::default(), |mut totals, point| {
            totals.bytes_in = totals.bytes_in.saturating_add(point.bytes_in);
            totals.bytes_out = totals.bytes_out.saturating_add(point.bytes_out);
            totals.payload_in = totals.payload_in.saturating_add(point.payload_in);
            totals.payload_out = totals.payload_out.saturating_add(point.payload_out);
            totals
        });
    Ok(Json(json!({
        "range": range,
        "from": from,
        "to": to,
        "step": step,
        "series": points.iter().map(|point| json!({
            "ts": point.ts,
            "bytes_in": point.bytes_in,
            "bytes_out": point.bytes_out,
            "payload_in": point.payload_in,
            "payload_out": point.payload_out,
        })).collect::<Vec<_>>(),
        "totals": totals,
    })))
}

#[derive(Deserialize)]
struct SessionsQuery {
    #[serde(default)]
    limit: Option<usize>,
}

async fn peer_sessions(
    State(state): State<Arc<AdminState>>,
    AxumPath(id): AxumPath<String>,
    Query(query): Query<SessionsQuery>,
) -> Result<Json<Value>, ApiError> {
    let id = parse_id(&id).map_err(ApiError::bad)?;
    let limit = query.limit.unwrap_or(50).min(500);
    let rows = state
        .db(move |store| store.list_sessions(&id, limit))
        .await?;
    Ok(Json(json!({
        "sessions": rows.iter().map(|row| json!({
            "session_id": row.session_id,
            "started_at": rfc3339(row.started_at),
            "ended_at": row.ended_at.map(rfc3339),
            "end_reason": row.end_reason,
            "addr": row.addr,
            "proto": row.proto,
            "mode": row.mode,
            "counters": row.counters,
        })).collect::<Vec<_>>(),
    })))
}

async fn list_sessions(State(state): State<Arc<AdminState>>) -> Json<Value> {
    let sessions = state.sessions_with_rates().await;
    Json(json!({
        "sessions": sessions,
        "count": sessions.len(),
    }))
}

// ---- system -------------------------------------------------------------

async fn system_status(State(state): State<Arc<AdminState>>) -> Json<Value> {
    let mut status = state.backend.system_status().await;
    status.counters.admin_hook_dropped = state.history.dropped();
    Json(json!(status))
}

async fn system_events(State(state): State<Arc<AdminState>>) -> Json<Value> {
    Json(json!({ "events": state.backend.events() }))
}

async fn get_config(State(state): State<Arc<AdminState>>) -> Result<Json<Value>, ApiError> {
    let snapshot = state.backend.config_snapshot().await?;
    let status = state.backend.system_status().await;
    let sessions = state.sessions_with_rates().await;
    let peers = build_peer_views(
        &snapshot,
        &sessions,
        &HashMap::new(),
        &HashMap::new(),
        &HashMap::new(),
    );
    Ok(Json(json!({
        "etag": snapshot.etag,
        "generation": status.config.generation,
        "enabled_yaml": snapshot.enabled_yaml,
        "disabled_yaml": snapshot.disabled_yaml,
        "peers": peers,
        "config_status": status.config,
        "warnings": config_warnings(&snapshot.files),
    })))
}

#[derive(Deserialize)]
struct ConfigPreviewRequest {
    enabled_yaml: String,
    disabled_yaml: String,
}

async fn preview_config(
    State(state): State<Arc<AdminState>>,
    Json(request): Json<ConfigPreviewRequest>,
) -> Result<Json<PreviewReport>, ApiError> {
    let report = state
        .backend
        .preview_config(&request.enabled_yaml, &request.disabled_yaml)
        .await?;
    Ok(Json(report))
}

async fn apply_config(
    State(state): State<Arc<AdminState>>,
    Extension(ctx): Extension<AuthContext>,
    headers: HeaderMap,
    Json(request): Json<ApplyRequest>,
) -> Result<Json<ApplyReport>, ApiError> {
    let comment = request.comment.clone();
    let report = state.backend.apply_config(request).await?;
    state
        .audit(
            &ctx.user.username,
            &client_ip(&headers),
            "config.apply",
            "peers.yaml",
            json!({
                "comment": comment,
                "backups": report.backups,
                "revoked": report.revoked,
            }),
            "ok",
        )
        .await;
    Ok(Json(report))
}

async fn list_backups(State(state): State<Arc<AdminState>>) -> Result<Json<Value>, ApiError> {
    let backups = state.backend.list_backups().await?;
    Ok(Json(json!({ "backups": backups })))
}

#[derive(Deserialize)]
struct RestoreRequest {
    name: String,
    #[serde(default)]
    comment: String,
}

async fn restore_backup(
    State(state): State<Arc<AdminState>>,
    Extension(ctx): Extension<AuthContext>,
    headers: HeaderMap,
    Json(request): Json<RestoreRequest>,
) -> Result<Json<ApplyReport>, ApiError> {
    let name = request.name.clone();
    let report = state
        .backend
        .restore_backup(&request.name, request.comment.clone())
        .await?;
    state
        .audit(
            &ctx.user.username,
            &client_ip(&headers),
            "config.restore",
            &name,
            json!({"comment": request.comment}),
            "ok",
        )
        .await;
    Ok(Json(report))
}

#[derive(Deserialize)]
struct AuditQuery {
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    before: Option<i64>,
}

async fn list_audit(
    State(state): State<Arc<AdminState>>,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Value>, ApiError> {
    let limit = query.limit.unwrap_or(100).min(1000);
    let before = query.before;
    let rows = state
        .db(move |store| store.list_audit(limit, before))
        .await?;
    Ok(Json(json!({
        "audit": rows.iter().map(|row| json!({
            "id": row.id,
            "ts": rfc3339(row.ts),
            "user": row.user,
            "ip": row.ip,
            "action": row.action,
            "target": row.target,
            "detail": row.detail,
            "result": row.result,
        })).collect::<Vec<_>>(),
    })))
}

async fn sse_events(
    State(state): State<Arc<AdminState>>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let stream = IntervalStream::new(tokio::time::interval(std::time::Duration::from_secs(1)))
        .then(move |_| {
            let state = state.clone();
            async move {
                let sessions = state.sessions_with_rates().await;
                let rate_in: u64 = sessions.iter().map(|s| s.rate_in_bps).sum();
                let rate_out: u64 = sessions.iter().map(|s| s.rate_out_bps).sum();
                let payload = json!({
                    "ts": now_unix(),
                    "online": sessions.len(),
                    "rate_in_bps": rate_in,
                    "rate_out_bps": rate_out,
                    "sessions": sessions.iter().map(|s| json!({
                        "session_id": s.session_id,
                        "peer_id": s.peer_id,
                        "name": s.name,
                        "rate_in_bps": s.rate_in_bps,
                        "rate_out_bps": s.rate_out_bps,
                    })).collect::<Vec<_>>(),
                });
                let event = Event::default()
                    .event("tick")
                    .json_data(payload)
                    .unwrap_or_else(|_| Event::default().event("tick").data("{}"));
                Ok(event)
            }
        });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn metrics(State(state): State<Arc<AdminState>>) -> Response {
    let status = state.backend.system_status().await;
    let sessions = state.sessions_with_rates().await;
    let snapshot = state.backend.config_snapshot().await.ok();
    let lifetimes = state
        .db(|store| store.lifetime_all())
        .await
        .unwrap_or_default();
    let today = day_start();
    let (today_in, today_out) = state
        .db(move |store| store.total_usage_all(today))
        .await
        .unwrap_or_default();

    let mut body = String::new();
    body.push_str("# HELP rustvpn_up Whether the daemon is running\n");
    body.push_str("# TYPE rustvpn_up gauge\nrustvpn_up 1\n");
    body.push_str(&format!(
        "rustvpn_uptime_seconds {}\n",
        status.uptime_seconds
    ));
    body.push_str(&format!(
        "rustvpn_peers_active {}\nrustvpn_peers_configured {}\nrustvpn_peers_disabled {}\n",
        sessions.len(),
        status.configured_peers,
        status.disabled_peers
    ));
    body.push_str(&format!(
        "rustvpn_today_payload_in_bytes {today_in}\nrustvpn_today_payload_out_bytes {today_out}\n"
    ));

    if let Some(snapshot) = &snapshot {
        for (name, peer) in snapshot
            .files
            .enabled
            .iter()
            .chain(snapshot.files.disabled.iter())
        {
            let Some(id) = peer_id_of(peer) else { continue };
            let id = id_hex(&id);
            let label = format!("peer=\"{}\",id=\"{}\"", escape_label(name), id);
            let totals = lifetimes
                .get(&peer_id_of(peer).unwrap())
                .copied()
                .unwrap_or_default();
            let online = sessions.iter().any(|s| s.peer_id == id);
            body.push_str(&format!(
                "rustvpn_peer_payload_in_bytes_total{{{label}}} {}\n",
                totals.payload_in
            ));
            body.push_str(&format!(
                "rustvpn_peer_payload_out_bytes_total{{{label}}} {}\n",
                totals.payload_out
            ));
            body.push_str(&format!(
                "rustvpn_peer_wire_in_bytes_total{{{label}}} {}\n",
                totals.bytes_in
            ));
            body.push_str(&format!(
                "rustvpn_peer_wire_out_bytes_total{{{label}}} {}\n",
                totals.bytes_out
            ));
            body.push_str(&format!(
                "rustvpn_peer_online{{{label}}} {}\n",
                if online { 1 } else { 0 }
            ));
        }
    }
    body.push_str(&format!(
        "rustvpn_sessions_started_total {}\nrustvpn_sessions_finished_total {}\n\
         rustvpn_handshake_requests_total {}\nrustvpn_handshake_rate_limited_total {}\n\
         rustvpn_handshake_errors_total {}\nrustvpn_tcp_connections_rejected_total {}\n\
         rustvpn_config_reload_errors_total {}\n",
        status.counters.sessions_started,
        status.counters.sessions_finished,
        status.counters.handshake_requests,
        status.counters.handshake_rate_limited,
        status.counters.handshake_errors,
        status.counters.tcp_connections_rejected,
        if status.config.last_error.is_some() {
            1
        } else {
            0
        },
    ));
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body).into_response()
}

// ---- helpers ------------------------------------------------------------

fn build_peer_views(
    snapshot: &ConfigSnapshot,
    sessions: &[SessionInfo],
    meta: &HashMap<PeerId, crate::store::PeerMeta>,
    lifetimes: &HashMap<PeerId, TrafficTotals>,
    usage: &HashMap<PeerId, u64>,
) -> Vec<PeerView> {
    let mut out = Vec::with_capacity(snapshot.files.enabled.len() + snapshot.files.disabled.len());
    for (enabled, map) in [
        (true, &snapshot.files.enabled),
        (false, &snapshot.files.disabled),
    ] {
        for (name, peer) in map {
            let Some(id) = peer_id_of(peer) else { continue };
            let id_string = id_hex(&id);
            let session = sessions.iter().find(|s| s.peer_id == id_string);
            // Lifetime totals are stored on the session row and refreshed by
            // the sampler every 10s, so do not add the live counters again.
            let lifetime = lifetimes.get(&id).copied().unwrap_or_default();
            let meta = meta.get(&id);
            let abnormal = session
                .map(|s| s.counters.unauth > 0 || s.counters.dup > 0)
                .unwrap_or(false);
            let state = if !enabled {
                "disabled"
            } else if session.is_none() {
                "offline"
            } else if abnormal {
                "abnormal"
            } else {
                "online"
            };
            out.push(PeerView {
                id: id_string,
                name: name.clone(),
                enabled,
                state: state.into(),
                session_id: session.map(|s| s.session_id),
                addr: session.map(|s| s.addr.clone()),
                proto: session.map(|s| s.proto.clone()),
                mode: mode_name(peer.noise, peer.encless).into(),
                mtu: if peer.mtu == 0 { MTU_DEFAULT } else { peer.mtu },
                iface: peer.iface.clone(),
                established: session.map(|s| s.established.clone()),
                last_ping: session.map(|s| s.last_ping.clone()),
                uptime_seconds: session.map(|s| (now_unix() - s.started_at_unix).max(0) as u64),
                rate_in_bps: session.map(|s| s.rate_in_bps).unwrap_or(0),
                rate_out_bps: session.map(|s| s.rate_out_bps).unwrap_or(0),
                session: session.map(|s| s.counters).unwrap_or_default(),
                lifetime,
                notes: meta.and_then(|m| m.notes.clone()),
                quota_bytes_month: meta.and_then(|m| m.quota_bytes_month),
                month_usage: usage.get(&id).copied().unwrap_or(0),
            });
        }
    }
    out
}

fn config_warnings(files: &ConfigFiles) -> Vec<String> {
    files.validate().unwrap_or_default()
}

fn client_command(name: &str, peer: &PeerYaml, short_verifier: &str) -> String {
    format!(
        "# {name}\nrustvpn-client -remote <SERVER>:1194 -proto udp -iface {} -mtu {} \
         -timeout {} -verifier '{}' -key /etc/rustvpn/pass",
        if peer.iface.is_empty() {
            "tap0".to_string()
        } else {
            peer.iface.clone()
        },
        if peer.mtu == 0 { MTU_DEFAULT } else { peer.mtu },
        if peer.timeout <= 0 { 60 } else { peer.timeout },
        short_verifier
    )
}

fn generated_password() -> Result<String, ApiError> {
    let password = auth::generate_password(32);
    if password.is_empty() {
        Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "random source failed",
        ))
    } else {
        Ok(password)
    }
}

fn cookie_name(secure: bool) -> &'static str {
    if secure {
        "__Host-rvpn_admin"
    } else {
        "rvpn_admin"
    }
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some((key, value)) = part.split_once('=') {
            if key == name {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn client_ip(headers: &HeaderMap) -> String {
    for name in ["x-forwarded-for", "x-real-ip"] {
        if let Some(value) = headers.get(name).and_then(|v| v.to_str().ok()) {
            if let Some(first) = value.split(',').next() {
                let first = first.trim();
                if !first.is_empty() {
                    return first.to_string();
                }
            }
        }
    }
    "local".to_string()
}

fn day_start() -> i64 {
    let now = Utc::now();
    Utc.with_ymd_and_hms(now.year(), now.month(), now.day(), 0, 0, 0)
        .single()
        .map(|t| t.timestamp())
        .unwrap_or_else(|| now.timestamp())
}

fn month_start() -> i64 {
    let now = Utc::now();
    Utc.with_ymd_and_hms(now.year(), now.month(), 1, 0, 0, 0)
        .single()
        .map(|t| t.timestamp())
        .unwrap_or_else(|| now.timestamp())
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::History;
    use crate::model::{
        AdminBackend, BackupInfo, ConfigSnapshot, ConfigStatus, EventView, KickReport,
        ServerCounters, SystemStatus,
    };
    use crate::store::Store;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use serde_json::Value;
    use tower::ServiceExt;

    struct FakeBackend;

    #[async_trait::async_trait]
    impl AdminBackend for FakeBackend {
        async fn system_status(&self) -> SystemStatus {
            SystemStatus {
                uptime_seconds: 1,
                bind: "127.0.0.1:1194".into(),
                proto: "udp".into(),
                admin_addr: "127.0.0.1:8080".into(),
                active_sessions: 0,
                configured_peers: 0,
                disabled_peers: 0,
                config: ConfigStatus {
                    path: "peers.yaml".into(),
                    disabled_path: "peers.disabled.yaml".into(),
                    generation: 1,
                    last_loaded_at: None,
                    last_error: None,
                    etag: "test-etag".into(),
                },
                counters: ServerCounters::default(),
            }
        }

        async fn config_snapshot(&self) -> Result<ConfigSnapshot, ConfigError> {
            Ok(ConfigSnapshot {
                enabled_yaml: String::new(),
                disabled_yaml: String::new(),
                etag: "test-etag".into(),
                files: ConfigFiles::default(),
            })
        }

        async fn preview_config(
            &self,
            _enabled_yaml: &str,
            _disabled_yaml: &str,
        ) -> Result<PreviewReport, ConfigError> {
            Ok(PreviewReport {
                valid: true,
                errors: Vec::new(),
                warnings: Vec::new(),
                added: Vec::new(),
                removed: Vec::new(),
                changed: Vec::new(),
                revoked: Vec::new(),
            })
        }

        async fn apply_config(&self, _request: ApplyRequest) -> Result<ApplyReport, ConfigError> {
            Ok(ApplyReport {
                applied: true,
                generation: 2,
                etag: "next-etag".into(),
                backups: Vec::new(),
                revoked: Vec::new(),
                warnings: Vec::new(),
            })
        }

        async fn active_sessions(&self) -> Vec<SessionInfo> {
            Vec::new()
        }

        async fn kick(&self, _id: PeerId, _reason: String) -> Result<KickReport, String> {
            Err("not online".into())
        }

        async fn list_backups(&self) -> Result<Vec<BackupInfo>, ConfigError> {
            Ok(Vec::new())
        }

        async fn restore_backup(
            &self,
            _name: &str,
            _comment: String,
        ) -> Result<ApplyReport, ConfigError> {
            Ok(ApplyReport {
                applied: true,
                generation: 3,
                etag: "restored".into(),
                backups: Vec::new(),
                revoked: Vec::new(),
                warnings: Vec::new(),
            })
        }

        fn events(&self) -> Vec<EventView> {
            Vec::new()
        }
    }

    async fn test_state() -> Arc<AdminState> {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let (salt, hash) = auth::hash_password("test-password-123", 1024, 2, 1).unwrap();
        store
            .upsert_admin("admin", "admin", &salt, &hash, 1024, 2, 1)
            .unwrap();
        let history = History::spawn(store.clone());
        AdminState::new(
            Arc::new(FakeBackend),
            store,
            history,
            crate::AdminOptions::default(),
        )
    }

    async fn response_json(response: Response) -> Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn health_is_public() {
        let app = router(test_state().await);
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn peers_require_login() {
        let app = router(test_state().await);
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/peers")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_cookie_grants_access_and_csrf_is_enforced() {
        let state = test_state().await;
        let app = router(state);

        let login = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::POST)
                    .uri("/api/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"username":"admin","password":"test-password-123"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::OK);
        let cookie = login
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let body = response_json(login).await;
        let csrf = body["csrf_token"].as_str().unwrap().to_string();

        let peers = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/peers")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(peers.status(), StatusCode::OK);
        let body = response_json(peers).await;
        assert!(body["peers"].is_array());

        let without_csrf = app
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::POST)
                    .uri("/api/peers")
                    .header(header::COOKIE, &cookie)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(without_csrf.status(), StatusCode::FORBIDDEN);

        // Suppress an unused-variable warning while keeping the token visible
        // for future mutation tests.
        assert_eq!(csrf.len(), 64);
    }

    #[tokio::test]
    async fn static_assets_are_embedded() {
        let app = router(test_state().await);
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/app.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("javascript"));
    }
}
