use crate::dns::DnsServer;

#[derive(Clone)]
pub struct AppState {
    pub dns_server: DnsServer
}
