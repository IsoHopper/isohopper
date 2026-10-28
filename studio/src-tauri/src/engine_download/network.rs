use super::{DOWNLOAD_URL, Download};
use std::time::Duration;

pub(super) fn allowed_redirect(url: &reqwest::Url, previous: usize) -> bool {
    previous <= 4
        && url.scheme() == "https"
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
        && matches!(
            url.host_str(),
            Some("github.com" | "release-assets.githubusercontent.com")
        )
}

pub(super) fn client_builder() -> reqwest::blocking::ClientBuilder {
    // Keep the body-total deadline in the async transport. Use the blocking
    // wrapper for per-read deadlines: reqwest's async read_timeout creates a
    // Tokio timer while a blocking Response is polled outside its runtime.
    let builder = reqwest::Client::builder()
        .tls_backend_native()
        .tls_version_min(reqwest::tls::Version::TLS_1_2)
        .https_only(true)
        .no_proxy()
        .referer(false)
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .retry(reqwest::retry::never())
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(180))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if allowed_redirect(attempt.url(), attempt.previous().len()) {
                attempt.follow()
            } else {
                attempt.error("Engine download redirect is not allowed.")
            }
        }));
    reqwest::blocking::ClientBuilder::from(builder).timeout(Duration::from_secs(15))
}

pub(super) fn fetch() -> Result<Download, String> {
    let client = client_builder()
        .build()
        .map_err(|error| format!("Create HTTPS client: {}", error.without_url()))?;
    let response = client
        .get(DOWNLOAD_URL)
        .header(reqwest::header::ACCEPT, "application/octet-stream")
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .header(reqwest::header::USER_AGENT, "IsoHopper-Studio")
        .send()
        .map_err(|error| format!("Download engine archive: {}", error.without_url()))?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(format!(
            "Engine download returned HTTP {}.",
            response.status().as_u16()
        ));
    }
    if response
        .headers()
        .get(reqwest::header::CONTENT_ENCODING)
        .is_some_and(|value| value.as_bytes() != b"identity")
    {
        return Err("Engine download used an unexpected content encoding.".into());
    }
    Ok(Download {
        length: response.content_length(),
        body: Box::new(response),
    })
}
