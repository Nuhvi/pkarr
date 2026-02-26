//! HTTP client abstraction for relay requests.

use bytes::Bytes;
use std::future::Future;
use std::time::Duration;
use url::Url;

/// HTTP client trait for making requests to relays.
///
/// Implement this trait to use a custom HTTP client (e.g., `ureq`, `surf`, etc.)
/// instead of the default `reqwest` client.
pub trait HttpClient: Send + Sync {
    /// Perform a GET request.
    fn get(
        &self,
        url: Url,
        timeout: Duration,
        headers: &[(&str, &str)],
    ) -> Box<dyn Future<Output = Result<HttpResponse, HttpError>> + Send + Unpin>;

    /// Perform a PUT request.
    fn put(
        &self,
        url: Url,
        timeout: Duration,
        headers: &[(&str, &str)],
        body: Bytes,
    ) -> Box<dyn Future<Output = Result<HttpResponse, HttpError>> + Send + Unpin>;
}

/// Response from an HTTP request.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response body.
    pub body: Bytes,
}

/// Error from an HTTP request.
#[derive(Debug)]
pub struct HttpError {
    /// Error message.
    pub message: String,
    /// Whether the error was a timeout.
    pub is_timeout: bool,
    /// HTTP status code if any.
    pub status: Option<u16>,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for HttpError {}

#[cfg(feature = "default-http-client")]
mod reqwest_impl {
    use super::*;
    use reqwest::header::HeaderValue;

    /// A wrapper around `reqwest::Client` that implements [`HttpClient`].
    #[derive(Clone)]
    pub struct ReqwestClient(reqwest::Client);

    impl ReqwestClient {
        /// Create a new `ReqwestClient` from an existing `reqwest::Client`.
        #[allow(dead_code)]
        pub fn new(client: reqwest::Client) -> Self {
            ReqwestClient(client)
        }

        /// Create a new `ReqwestClient` with default settings.
        pub fn from_default() -> Self {
            ReqwestClient(
                reqwest::Client::builder()
                    .build()
                    .expect("reqwest Client building should be infallible"),
            )
        }
    }

    impl HttpClient for ReqwestClient {
        fn get(
            &self,
            url: Url,
            timeout: Duration,
            headers: &[(&str, &str)],
        ) -> Box<dyn Future<Output = Result<HttpResponse, HttpError>> + Send + Unpin> {
            let mut request = self.0.get(url).timeout(timeout);
            for (name, value) in headers {
                request = request.header(
                    *name,
                    HeaderValue::from_str(value).expect("valid header value"),
                );
            }
            Box::new(Box::pin(async move {
                let response = request.send().await?;
                Ok(HttpResponse {
                    status: response.status().as_u16(),
                    body: response.bytes().await?,
                })
            }))
        }

        fn put(
            &self,
            url: Url,
            timeout: Duration,
            headers: &[(&str, &str)],
            body: Bytes,
        ) -> Box<dyn Future<Output = Result<HttpResponse, HttpError>> + Send + Unpin> {
            let mut request = self.0.put(url).timeout(timeout);
            for (name, value) in headers {
                request = request.header(
                    *name,
                    HeaderValue::from_str(value).expect("valid header value"),
                );
            }
            Box::new(Box::pin(async move {
                let response = request.body(body).send().await?;
                Ok(HttpResponse {
                    status: response.status().as_u16(),
                    body: response.bytes().await?,
                })
            }))
        }
    }

    impl From<reqwest::Error> for HttpError {
        fn from(e: reqwest::Error) -> Self {
            HttpError {
                message: e.to_string(),
                is_timeout: e.is_timeout(),
                status: e.status().map(|s| s.as_u16()),
            }
        }
    }

    /// Create a default HTTP client.
    ///
    /// This is used internally when no custom client is provided.
    pub fn default_http_client() -> ReqwestClient {
        ReqwestClient::from_default()
    }
}

#[cfg(feature = "default-http-client")]
pub use reqwest_impl::{default_http_client, ReqwestClient};
