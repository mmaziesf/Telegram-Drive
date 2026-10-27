use actix_web::body::{EitherBody, MessageBody};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::{
    header::{HeaderValue, HOST},
    Uri,
};
use actix_web::middleware::Next;
use actix_web::HttpResponse;

#[cfg(debug_assertions)]
const DEVELOPMENT_FRONTEND_PORT: u16 = 1420;

/// Refuses any request whose Host header is not this server's loopback
/// address. The servers bind 127.0.0.1 only, but a web page can point a domain
/// it controls at 127.0.0.1 (DNS rebinding) and then reach them as same-origin;
/// such requests carry the attacker's host name and stop here with 421.
pub(crate) async fn require_loopback_host<B: MessageBody + 'static>(
    request: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<EitherBody<B>>, actix_web::Error> {
    let port = request.app_config().local_addr().port();
    let allowed = request
        .headers()
        .get(HOST)
        .and_then(|host| host.to_str().ok())
        .is_some_and(|host| is_loopback_host(host, port));
    if !allowed {
        let response = HttpResponse::MisdirectedRequest().body("Unexpected Host header");
        return Ok(request.into_response(response).map_into_right_body());
    }
    next.call(request)
        .await
        .map(ServiceResponse::map_into_left_body)
}

fn is_loopback_host(host: &str, port: u16) -> bool {
    let Some((name, host_port)) = host.rsplit_once(':') else {
        return false;
    };
    host_port.parse::<u16>().ok() == Some(port)
        && (name == "127.0.0.1" || name.eq_ignore_ascii_case("localhost"))
}

pub(crate) fn is_allowed_origin_header(origin: &HeaderValue) -> bool {
    origin.to_str().is_ok_and(is_allowed_origin)
}

fn is_allowed_origin(origin: &str) -> bool {
    // WebKit (macOS, Linux) sends `Origin: null` for media fetches from the
    // tauri:// scheme; without it playback fails there (v1.8.2). An opaque
    // origin still needs the stream token or API key to get anything private.
    if matches!(origin, "null" | "tauri://localhost") {
        return true;
    }

    let Ok(uri) = origin.parse::<Uri>() else {
        return false;
    };
    let Some(scheme) = uri.scheme_str() else {
        return false;
    };
    let Some(authority) = uri.authority() else {
        return false;
    };
    if authority.as_str().contains('@') || format!("{scheme}://{authority}") != origin {
        return false;
    }
    let host = authority.host();
    let port = authority.port_u16();

    matches!(
        (scheme, host, port),
        ("http", "tauri.localhost", None)
            | ("https", "tauri.localhost", None)
            | ("http", "asset.localhost", None)
            | ("https", "asset.localhost", None)
    ) || is_development_origin(scheme, host, port)
}

/// The Vite dev server origin is only trusted in debug builds.
#[cfg(debug_assertions)]
fn is_development_origin(scheme: &str, host: &str, port: Option<u16>) -> bool {
    matches!(
        (scheme, host, port),
        ("http", "localhost", Some(DEVELOPMENT_FRONTEND_PORT))
            | ("http", "127.0.0.1", Some(DEVELOPMENT_FRONTEND_PORT))
    )
}

#[cfg(not(debug_assertions))]
fn is_development_origin(_scheme: &str, _host: &str, _port: Option<u16>) -> bool {
    false
}
