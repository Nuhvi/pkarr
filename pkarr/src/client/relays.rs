use std::collections::HashMap;
use std::fmt::Debug;
#[cfg(not(wasm_browser))]
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use futures_buffered::FuturesUnorderedBounded;
#[cfg(not(wasm_browser))]
use futures_lite::Stream;
use futures_lite::StreamExt;
use ntimestamp::Timestamp;
use url::Url;

use crate::client::http::{HttpClient, HttpError};

use super::{ConcurrencyError, PublishError, QueryError};
use crate::{PublicKey, SignedPacket};

#[derive(Clone)]
pub struct RelaysClient {
    relays: Box<[Url]>,
    http_client: Arc<dyn HttpClient>,
    timeout: Duration,
    pub(crate) inflight_publish: InflightPublishRequests,
}

impl Debug for RelaysClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("RelaysClient");

        debug_struct.field(
            "relays",
            &self
                .relays
                .as_ref()
                .iter()
                .map(|url| url.as_str())
                .collect::<Vec<_>>(),
        );

        debug_struct.finish()
    }
}

impl RelaysClient {
    pub fn new(relays: Box<[Url]>, http_client: Arc<dyn HttpClient>, timeout: Duration) -> Self {
        let inflight_publish = InflightPublishRequests::new(relays.len());

        Self {
            relays,
            http_client,
            timeout,
            inflight_publish,
        }
    }

    pub async fn publish(
        &self,
        signed_packet: &SignedPacket,
        cas: Option<Timestamp>,
    ) -> Result<(), PublishError> {
        let public_key = signed_packet.public_key();

        self.inflight_publish
            .start_request(&public_key, signed_packet, cas)?;

        let mut futures = futures_buffered::FuturesUnorderedBounded::new(self.relays.len());

        let body = signed_packet.to_relay_payload();
        let cas = cas.map(|timestamp| timestamp.as_u64().to_string());

        for relay in &self.relays {
            let http_client = self.http_client.clone();
            let timeout = self.timeout;

            let cas = cas.clone();
            let body = body.clone();

            let public_key = public_key.clone();
            let relay = relay.clone();

            let mut inflight = self.inflight_publish.clone();

            futures.push(async move {
                let result = publish_to_relay(http_client, relay, &public_key, body, cas, timeout)
                    .await
                    .map_err(map_http_error);

                inflight.add_result(&public_key, result)
            });
        }

        futures
            .filter_map(|result| match result {
                Ok(true) => Some(Ok(())),
                Ok(false) => None,
                Err(err) => Some(Err(err)),
            })
            .next()
            .await
            .expect("relays inflight publish requests done with no success or error!")
    }

    #[cfg(not(wasm_browser))]
    /// Cancel an inflight publish request.
    pub fn cancel_publish(&self, public_key: &PublicKey) {
        self.inflight_publish.cancel_request(public_key);
    }

    #[cfg(not(wasm_browser))]
    pub fn resolve(
        &self,
        public_key: &PublicKey,
        more_recent_than: Option<Timestamp>,
    ) -> Pin<Box<dyn Stream<Item = SignedPacket> + Send>> {
        Box::pin(
            self.resolve_futures(public_key, more_recent_than)
                .filter_map(|opt| opt),
        )
    }

    pub fn resolve_futures(
        &self,
        public_key: &PublicKey,
        more_recent_than: Option<Timestamp>,
    ) -> FuturesUnorderedBounded<impl futures_lite::Future<Output = Option<SignedPacket>>> {
        let mut futures = FuturesUnorderedBounded::new(self.relays.len());

        let if_modified_since = more_recent_than.map(|t| t.format_http_date());

        self.relays.iter().for_each(|relay| {
            let http_client = self.http_client.clone();
            let relay = relay.clone();
            let public_key = public_key.clone();
            let if_modified_since = if_modified_since.clone();
            let timeout = self.timeout;

            futures.push(resolve_from_relay(
                http_client,
                relay,
                public_key,
                if_modified_since,
                timeout,
            ));
        });

        futures
    }
}

#[derive(Debug)]
struct InflightPublishRequest {
    signed_packet: SignedPacket,
    success_count: usize,
    errors: HashMap<PublishError, usize>,
}

#[derive(Clone, Debug)]
pub(crate) struct InflightPublishRequests {
    relays_count: usize,
    requests: Arc<Mutex<HashMap<PublicKey, InflightPublishRequest>>>,
}

impl InflightPublishRequests {
    fn new(relays_count: usize) -> Self {
        Self {
            relays_count,
            requests: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn start_request(
        &self,
        public_key: &PublicKey,
        signed_packet: &SignedPacket,
        cas: Option<Timestamp>,
    ) -> Result<(), PublishError> {
        let mut requests = self.requests.lock().expect("InflightPublishRequests lock");

        if let Some(inflight_request) = requests.get_mut(public_key) {
            if signed_packet.signature() == inflight_request.signed_packet.signature() {
            } else if !signed_packet.more_recent_than(&inflight_request.signed_packet) {
                return Err(ConcurrencyError::NotMostRecent)?;
            } else if let Some(cas) = cas {
                if cas != inflight_request.signed_packet.timestamp() {
                    return Err(ConcurrencyError::CasFailed)?;
                }
            } else {
                return Err(ConcurrencyError::ConflictRisk)?;
            };
        } else {
            requests.insert(
                public_key.clone(),
                InflightPublishRequest {
                    signed_packet: signed_packet.clone(),
                    success_count: 0,
                    errors: Default::default(),
                },
            );
        };

        Ok(())
    }

    #[cfg(not(wasm_browser))]
    pub fn cancel_request(&self, public_key: &PublicKey) {
        let mut inflight = self.requests.lock().expect("InflightPublishRequests lock");

        inflight.remove(public_key);
    }

    pub fn add_result(
        &mut self,
        public_key: &PublicKey,
        result: Result<(), PublishError>,
    ) -> Result<bool, PublishError> {
        match result {
            Ok(_) => self.add_success(public_key),
            Err(error) => self.add_error(public_key, error),
        }
    }

    fn add_success(&self, public_key: &PublicKey) -> Result<bool, PublishError> {
        let mut inflight = self.requests.lock().expect("InflightPublishRequests lock");

        if let Some(request) = inflight.get_mut(public_key) {
            let majority = self.relays_count / 2 + self.relays_count % 2;

            request.success_count += 1;

            if self.done(request) || request.success_count >= majority {
                inflight.remove(public_key);

                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(true)
        }
    }

    fn add_error(
        &mut self,
        public_key: &PublicKey,
        error: PublishError,
    ) -> Result<bool, PublishError> {
        let mut inflight = self.requests.lock().expect("InflightPublishRequests lock");

        if let Some(request) = inflight.get_mut(public_key) {
            let majority = self.relays_count / 2 + self.relays_count % 2;

            {
                let count = request.errors.get(&error).unwrap_or(&0) + 1;

                if count >= majority
                    && matches!(
                        error,
                        PublishError::Concurrency(ConcurrencyError::NotMostRecent)
                    ) | matches!(
                        error,
                        PublishError::Concurrency(ConcurrencyError::CasFailed)
                    )
                {
                    inflight.remove(public_key);

                    return Err(error);
                }

                request.errors.insert(error, count);
            }

            if self.done(request) {
                let request = inflight.remove(public_key).expect("infallible");

                if request.success_count >= majority {
                    Ok(true)
                } else {
                    let most_common_error = request
                        .errors
                        .into_iter()
                        .max_by_key(|&(_, count)| count)
                        .map(|(error, _)| error)
                        .expect("infallible");

                    Err(most_common_error)
                }
            } else {
                Ok(false)
            }
        } else {
            Ok(true)
        }
    }

    fn done(&self, request: &InflightPublishRequest) -> bool {
        let total_errors: usize = request.errors.values().sum();
        (total_errors + request.success_count) >= self.relays_count
    }
}

pub async fn publish_to_relay(
    http_client: Arc<dyn HttpClient>,
    relay: Url,
    public_key: &PublicKey,
    body: Bytes,
    cas: Option<String>,
    timeout: Duration,
) -> Result<(), HttpError> {
    let url = format_url(&relay, public_key);

    let mut headers: Vec<(&str, &str)> = Vec::new();
    if let Some(ref cas) = cas {
        headers.push(("if-match", cas.as_str()));
    }

    let response = http_client
        .put(url.clone(), timeout * 3, &headers, body)
        .await?;

    let status = response.status;

    if !(200..300).contains(&status) {
        let text = String::from_utf8_lossy(&response.body);

        cross_debug!("Got error response for PUT {url} {status} {text}");

        return Err(HttpError {
            message: format!("HTTP error {status}: {text}"),
            is_timeout: false,
            status: Some(status),
        });
    }

    if status.is_success() {
        cross_debug!("Successfully published to {url}");
    } else {
        cross_debug!("Got neither 2xx nor >=400 status code {status} for PUT {url}",);
    }

    Ok(())
}

fn map_http_error(error: HttpError) -> PublishError {
    if error.is_timeout {
        PublishError::Query(QueryError::Timeout)
    } else if let Some(status) = error.status {
        match status {
            400 => PublishError::Query(QueryError::BadRequest),
            409 => PublishError::Concurrency(ConcurrencyError::NotMostRecent),
            412 => PublishError::Concurrency(ConcurrencyError::CasFailed),
            428 => PublishError::Concurrency(ConcurrencyError::ConflictRisk),
            _ => PublishError::UnexpectedResponses,
        }
    } else {
        PublishError::UnexpectedResponses
    }
}

pub fn format_url(relay: &Url, public_key: &PublicKey) -> Url {
    let mut url = relay.clone();

    let mut segments = url
        .path_segments_mut()
        .expect("Relay url cannot be base, is it http(s)?");

    segments.push(&public_key.to_string());

    drop(segments);

    url
}

pub async fn resolve_from_relay(
    http_client: Arc<dyn HttpClient>,
    relay: Url,
    public_key: PublicKey,
    if_modified_since: Option<String>,
    timeout: Duration,
) -> Option<SignedPacket> {
    let url = format_url(&relay, &public_key);

    let mut headers = Vec::new();
    if let Some(ref httpdate) = if_modified_since {
        headers.push(("if-modified-since", httpdate.as_str()));
    }

    let mut response = match http_client.get(url.clone(), timeout, &headers).await {
        Ok(response) => response,
        Err(error) => {
            cross_debug!("GET {:?}", error);

            return None;
        }
    };

    let status = response.status;

    if !(200..300).contains(&status) {
        let text = String::from_utf8_lossy(&response.body);

        cross_debug!("Got error response for GET {url} {status} {text}");

        return None;
    };

    if status == 304 && if_modified_since.is_none() {
        let headers = vec![("cache-control", "no-cache, no-store, must-revalidate")];
        match http_client.get(url.clone(), timeout, &headers).await {
            Ok(resp) => {
                response = resp;
            }
            Err(error) => {
                cross_debug!("GET with no-cache {:?}", error);
                return None;
            }
        }
    }

    if status == 200 && response.body.is_empty() {
        let headers = vec![("cache-control", "no-cache, no-store, must-revalidate")];
        match http_client.get(url.clone(), timeout, &headers).await {
            Ok(resp) => {
                response = resp;
            }
            Err(error) => {
                cross_debug!("GET with no-cache {:?}", error);
                return None;
            }
        }
    }

    if response.body.len() as u64 > SignedPacket::MAX_BYTES {
        cross_debug!("Response too large for GET {url}");

        return None;
    }

    match SignedPacket::from_relay_payload(&public_key, &response.body) {
        Ok(signed_packet) => Some(signed_packet),
        Err(error) => {
            cross_debug!("Invalid signed_packet {url}:{error}");

            None
        }
    }
}

trait HttpStatusExt {
    fn is_success(&self) -> bool;
}

impl HttpStatusExt for u16 {
    fn is_success(&self) -> bool {
        (200..300).contains(self)
    }
}
