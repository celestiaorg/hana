use celestia_rpc::Client;
use celestia_types::nmt::Namespace;
use std::sync::Arc;

/// Online client to fetch data from a Celestia network
#[derive(Clone)]
pub struct OnlineCelestiaProvider {
    /// The node client
    pub client: Arc<Client>,
    /// The namespace to fetch data from
    pub namespace: Namespace,
}

impl OnlineCelestiaProvider {
    pub fn new(client: Client, namespace: Namespace) -> Self {
        OnlineCelestiaProvider {
            client: Arc::new(client),
            namespace,
        }
    }
}

impl core::fmt::Debug for OnlineCelestiaProvider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OnlineCelestiaProvider")
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}
