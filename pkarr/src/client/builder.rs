use std::sync::Arc;

#[cfg(relays)]
use std::time::Duration;

#[cfg(feature = "relays")]
use url::Url;

#[cfg(feature = "relays")]
use crate::client::http::HttpClient;
#[cfg(dht)]
use crate::mainline;
use crate::{errors::BuildError, Client};
use crate::{Cache, DEFAULT_CACHE_SIZE, DEFAULT_MAXIMUM_TTL, DEFAULT_MINIMUM_TTL};

#[cfg(feature = "endpoints")]
pub const DEFAULT_MAX_RECURSION_DEPTH: u8 = 7;

/// Default request timeout for relays requests.
#[cfg(relays)]
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// [Client]'s Config
#[derive(Clone)]
pub(crate) struct Config {
    /// Configures the [crate::InMemoryCache] size, if no [Self::cache] is set.
    ///
    /// Defaults to [DEFAULT_CACHE_SIZE]
    pub cache_size: usize,
    /// Used in the `min` parameter in [crate::SignedPacket::expires_in].
    ///
    /// Defaults to [DEFAULT_MINIMUM_TTL]
    pub minimum_ttl: u32,
    /// Used in the `max` parameter in [crate::SignedPacket::expires_in].
    ///
    /// Defaults to [DEFAULT_MAXIMUM_TTL]
    pub maximum_ttl: u32,
    /// Custom [Cache] implementation, defaults to [crate::InMemoryCache]
    pub cache: Option<Arc<dyn Cache>>,

    #[cfg(dht)]
    pub dht: Option<mainline::DhtBuilder>,

    /// Pkarr [Relays](https://pkarr.org/relays) Urls
    #[cfg(feature = "relays")]
    pub relays: Option<Vec<Url>>,

    /// Custom HTTP client for relay requests.
    #[cfg(feature = "relays")]
    pub http_client: Option<Arc<dyn HttpClient>>,

    /// Timeout for Relays requests (The Dht uses an adaptive timeout based on observed RTTs).
    ///
    /// The longer this timeout the longer resolve queries will take before consider failed.
    ///
    /// Defaults to [DEFAULT_REQUEST_TIMEOUT]
    #[cfg(feature = "relays")]
    pub request_timeout: Duration,

    #[cfg(feature = "endpoints")]
    pub max_recursion_depth: u8,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            cache_size: DEFAULT_CACHE_SIZE,
            minimum_ttl: DEFAULT_MINIMUM_TTL,
            maximum_ttl: DEFAULT_MAXIMUM_TTL,
            cache: None,

            #[cfg(dht)]
            dht: Some(mainline::Dht::builder()),

            #[cfg(feature = "relays")]
            relays: Some(
                crate::DEFAULT_RELAYS
                    .iter()
                    .map(|s| {
                        Url::parse(s).expect("DEFAULT_RELAYS should be parsed to Url successfully.")
                    })
                    .collect(),
            ),

            #[cfg(feature = "relays")]
            http_client: None,

            #[cfg(relays)]
            request_timeout: DEFAULT_REQUEST_TIMEOUT,

            #[cfg(feature = "endpoints")]
            max_recursion_depth: DEFAULT_MAX_RECURSION_DEPTH,
        }
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("Config");

        debug_struct.field("cache_size", &self.cache_size);
        debug_struct.field("minimum_ttl", &self.minimum_ttl);
        debug_struct.field("maximum_ttl", &self.maximum_ttl);
        debug_struct.field("cache", &self.cache);

        #[cfg(dht)]
        debug_struct.field("dht", &self.dht);
        #[cfg(dht)]
        #[cfg(feature = "relays")]
        debug_struct.field(
            "relays",
            &self
                .relays
                .as_ref()
                .map(|urls| urls.iter().map(|url| url.as_str()).collect::<Vec<_>>()),
        );

        #[cfg(feature = "relays")]
        debug_struct.field("request_timeout", &self.request_timeout);

        #[cfg(feature = "relays")]
        debug_struct.field("http_client", &self.http_client.is_some());

        debug_struct.finish()
    }
}

/// A builder for constructing a [`Client`] with custom configuration.
#[derive(Debug, Default, Clone)]
pub struct ClientBuilder(Config);

impl ClientBuilder {
    /// Similar to crates `no-default-features`, this method will remove the default [Self::bootstrap], and [Self::relays]
    /// effectively disabling the use of both [mainline] and [Relays](https://pkarr.org/relays).
    ///
    /// Or you can use [Self::relays] to use custom [Relays](https://pkarr.org/relays).
    ///
    /// Similarly you can use [Self::bootstrap] or [Self::dht] to use [mainline] with custom configurations.
    pub fn no_default_network(&mut self) -> &mut Self {
        self.no_dht();
        self.no_relays();

        self
    }

    /// Disable relays, and use the Dht only.
    pub fn no_dht(&mut self) -> &mut Self {
        #[cfg(dht)]
        {
            self.0.dht = None;
        }

        self
    }

    #[cfg(dht)]
    /// Create a [mainline::DhtBuilder] if `None`, and allows mutating it with a callback function.
    pub fn dht<F>(&mut self, f: F) -> &mut Self
    where
        F: FnOnce(&mut mainline::DhtBuilder) -> &mut mainline::DhtBuilder,
    {
        if self.0.dht.is_none() {
            self.0.dht = Some(Default::default());
        }

        if let Some(ref mut builder) = self.0.dht {
            f(builder);
        };

        self
    }

    /// Convenient method to set the `bootstrap` nodes in [Self::dht].
    ///
    /// You can start a separate Dht network by setting this to an empty array.
    ///
    /// If you want to extend [bootstrap][mainline::DhtBuilder::bootstrap] nodes with more nodes, you can
    /// use [Self::extra_bootstrap].
    #[cfg(dht)]
    pub fn bootstrap<T: ToString>(&mut self, bootstrap: &[T]) -> &mut Self {
        self.dht(|b| b.bootstrap(bootstrap));

        self
    }

    #[cfg(dht)]
    /// Extend the DHT bootstrapping nodes.
    ///
    /// If you want to set (override) the DHT bootstrapping nodes,
    /// use [Self::bootstrap] directly.
    pub fn extra_bootstrap<T: ToString>(&mut self, bootstrap: &[T]) -> &mut Self {
        self.dht(|b| b.extra_bootstrap(bootstrap));

        self
    }

    /// Disable relays, and use the Dht only.
    pub fn no_relays(&mut self) -> &mut Self {
        #[cfg(feature = "relays")]
        {
            self.0.relays = None;
        }

        self
    }

    /// Set custom set of [Relays](https://pkarr.org/relays).
    ///
    /// If you want to disable relays use [Self::no_relays] instead.
    #[cfg(feature = "relays")]
    pub fn relays<T: AsRef<str>>(&mut self, relays: &[T]) -> Result<&mut Self, InvalidRelayUrl> {
        let urls: Result<Vec<Url>, _> = relays.iter().map(|s| Url::parse(s.as_ref())).collect();

        let urls = urls.map_err(InvalidRelayUrl::Parse)?;

        for url in &urls {
            if url.scheme() != "http" && url.scheme() != "https" {
                return Err(InvalidRelayUrl::NotHttp(url.to_string()));
            }
        }
        self.0.relays = Some(urls);

        Ok(self)
    }

    #[cfg(feature = "relays")]
    /// Extend the current [Self::relays] with extra relays.
    ///
    /// If you want to set (override) relays instead, use [Self::relays]
    pub fn extra_relays<T: AsRef<str>>(
        &mut self,
        relays: &[T],
    ) -> Result<&mut Self, InvalidRelayUrl> {
        let urls: Result<Vec<Url>, _> = relays.iter().map(|s| Url::parse(s.as_ref())).collect();

        let urls = urls.map_err(InvalidRelayUrl::Parse)?;

        for url in &urls {
            if url.scheme() != "http" && url.scheme() != "https" {
                return Err(InvalidRelayUrl::NotHttp(url.to_string()));
            }
        }

        if let Some(ref mut existing) = self.0.relays {
            for relay in urls {
                if !existing.contains(&relay) {
                    existing.push(relay)
                }
            }
        }

        Ok(self)
    }

    /// Set the size of the capacity of the [Self::cache] implementation.
    ///
    /// If set to `0` cache will be disabled.
    pub fn cache_size(&mut self, cache_size: usize) -> &mut Self {
        self.0.cache_size = cache_size;

        self
    }

    /// Set the minimum TTL value.
    ///
    /// Limits how soon a [crate::SignedPacket] is considered expired.
    pub fn minimum_ttl(&mut self, ttl: u32) -> &mut Self {
        self.0.minimum_ttl = ttl;
        self.0.maximum_ttl = self.0.maximum_ttl.max(ttl);

        self
    }

    /// Set the maximum TTL value.
    ///
    /// Limits how long it takes before a [crate::SignedPacket] is considered expired.
    pub fn maximum_ttl(&mut self, ttl: u32) -> &mut Self {
        self.0.maximum_ttl = ttl;
        self.0.minimum_ttl = self.0.minimum_ttl.min(ttl);

        self
    }

    /// Set a custom implementation of [Cache].
    pub fn cache(&mut self, cache: Arc<dyn Cache>) -> &mut Self {
        self.0.cache = Some(cache);

        self
    }

    /// Set the maximum request timeout for relays client.
    ///
    /// Useful for testing NOT FOUND responses, where you want to reach the timeout
    /// sooner than the default of [DEFAULT_REQUEST_TIMEOUT].
    #[cfg(feature = "relays")]
    pub fn request_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.0.request_timeout = timeout;

        self
    }

    /// Set a custom HTTP client for relay requests.
    ///
    /// This allows you to use a different HTTP client implementation,
    /// such as a custom configured reqwest client, or a different HTTP library.
    ///
    /// By default, a reqwest client with default settings is used.
    #[cfg(feature = "relays")]
    pub fn http_client(&mut self, http_client: impl HttpClient + 'static) -> &mut Self {
        self.0.http_client = Some(Arc::new(http_client));

        self
    }

    #[cfg(feature = "endpoints")]
    /// Sets the maximum depth of recursion in [Endpoints](https://pkarr.org/endpoints) resolution.
    ///
    /// Similar to `bind9`'s [option](https://bind9.readthedocs.io/en/latest/reference.html#namedconf-statement-max-recursion-depth)
    ///
    /// Defaults to `7`
    pub fn max_recursion_depth(&mut self, max_recursion_depth: u8) -> &mut Self {
        self.0.max_recursion_depth = max_recursion_depth;

        self
    }

    /// Try building a [Client] with the configuration in this builder.
    pub fn build(&self) -> Result<Client, BuildError> {
        Client::new(self.0.clone())
    }
}

#[cfg(relays)]
#[derive(thiserror::Error, Debug)]
/// Errors occurring during building a [Client]
pub enum InvalidRelayUrl {
    #[error("Failed to parse into a Url: {0}")]
    /// Failed to parse into a Url.
    Parse(url::ParseError),

    #[error("Relays Urls should have `http` or `https`: {0}")]
    /// Relays Urls should have `http` or `https`.
    NotHttp(String),
}
