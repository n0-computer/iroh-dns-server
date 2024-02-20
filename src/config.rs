use crate::{
    dns::DnsConfig,
    http::{CertMode, HttpConfig, HttpsConfig},
};

pub struct Config {
    pub http: HttpConfig,
    pub dns: DnsConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            http: HttpConfig {
                http_port: Some(8080),
                https: Some(HttpsConfig {
                    port: 8443,
                    cert_hostname: "localhost".to_string(),
                    cert_mode: CertMode::SelfSigned,
                }),
            },
            dns: DnsConfig {
                // default_soa: "magic.".to_string(),
                default_soa:
                    "dns1.fission.systems hostmaster.fission.codes 0 10800 3600 604800 3600"
                        .to_string(),
                origin: "iroh.".to_string(),
                // users_origin: "user.magic.".to_string(),
                server_port: 5353,
                default_ttl: 900,
            },
        }
    }
}
