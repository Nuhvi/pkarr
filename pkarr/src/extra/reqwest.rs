use reqwest::dns::{Addrs, Resolve};

use crate::{Client, PublicKey};

use super::endpoints::EndpointResolver;

use std::net::ToSocketAddrs;

impl Resolve for Client {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let client = self.clone();
        Box::pin(resolve(client, name))
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "relay"))]
impl Resolve for crate::client::relay::Client {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let client = self.clone();
        Box::pin(resolve(client, name))
    }
}

async fn resolve(
    client: impl EndpointResolver,
    name: reqwest::dns::Name,
) -> Result<Addrs, Box<dyn std::error::Error + Send + Sync>> {
    let name = name.as_str();

    if PublicKey::try_from(name).is_ok() {
        let endpoint = client.resolve_endpoint(name).await?;

        let addrs: Addrs = Box::new(endpoint.to_socket_addrs().into_iter());

        return Ok(addrs);
    };

    Ok(Box::new(format!("{name}:0").to_socket_addrs().unwrap()))
}
