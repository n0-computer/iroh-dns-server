use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
};

use crate::{
    dns::DnsConfig,
    http::{CertMode, HttpConfig, HttpsConfig},
};

const DEFAULT_METRICS_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9117);

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub http: Option<HttpConfig>,
    pub https: Option<HttpsConfig>,
    pub dns: DnsConfig,
    pub metrics: Option<MetricsConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MetricsConfig {
    disabled: bool,
    bind_addr: Option<SocketAddr>,
}

impl MetricsConfig {
    pub fn disabled() -> Self {
        Self {
            disabled: true,
            bind_addr: None,
        }
    }
}

impl Config {
    pub async fn load(path: impl AsRef<Path>) -> Result<Config> {
        let s = tokio::fs::read_to_string(path.as_ref())
            .await
            .with_context(|| format!("failed to read {}", path.as_ref().to_string_lossy()))?;
        let config: Config = toml::from_str(&s)?;
        Ok(config)
    }

    pub fn data_dir() -> Result<PathBuf> {
        let dir = if let Some(val) = env::var_os("IROH_DNS_DATA_DIR") {
            PathBuf::from(val)
        } else {
            let path = dirs_next::data_dir().ok_or_else(|| {
                anyhow!("operating environment provides no directory for application data")
            })?;
            path.join("iroh-dns")
        };
        Ok(dir)
    }

    pub fn signed_packet_store_path() -> Result<PathBuf> {
        Ok(Self::data_dir()?.join("signed-packets-1.db"))
    }

    pub fn metrics_addr(&self) -> Option<SocketAddr> {
        match &self.metrics {
            None => Some(DEFAULT_METRICS_ADDR),
            Some(conf) => match conf.disabled {
                true => None,
                false => Some(conf.bind_addr.unwrap_or(DEFAULT_METRICS_ADDR)),
            },
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            http: Some(HttpConfig {
                port: 8080,
                bind_addr: None,
            }),
            https: Some(HttpsConfig {
                port: 8443,
                bind_addr: None,
                domains: vec!["localhost".to_string()],
                cert_mode: CertMode::SelfSigned,
                letsencrypt_contact: None,
                letsencrypt_prod: None,
            }),
            dns: DnsConfig {
                port: 5300,
                bind_addr: None,
                origins: vec!["irohdns.example.".to_string(), ".".to_string()],

                default_soa: "irohdns.example hostmaster.irohdns.example 0 10800 3600 604800 3600"
                    .to_string(),
                default_ttl: 900,

                rr_a: Some(Ipv4Addr::LOCALHOST),
                rr_aaaa: None,
                rr_ns: Some("ns1.irohdns.example.".to_string()),
            },
            metrics: None,
        }
    }
}
