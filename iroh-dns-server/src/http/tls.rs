
use std::{
    borrow::Cow,
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{bail, Context, Result};
use axum_server::{
    accept::Accept,
    tls_rustls::{RustlsAcceptor, RustlsConfig},
};
use futures::{future::BoxFuture, FutureExt};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls_acme::{axum::AxumAcceptor, caches::DirCache, AcmeConfig};
use tokio_stream::StreamExt;
use tracing::{debug, error, info_span, Instrument};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, strum::Display)]
#[serde(rename_all = "snake_case")]
pub enum CertMode {
    Manual,
    LetsEncrypt,
    SelfSigned,
}

impl CertMode {
    pub async fn build(&self, domain: &str, dir: PathBuf, contact: Option<String>, prod: bool) -> Result<TlsAcceptor> {
        Ok(match self {
            CertMode::Manual => TlsAcceptor::manual(domain, dir).await?,
            CertMode::SelfSigned => TlsAcceptor::self_signed(domain).await?,
            CertMode::LetsEncrypt=> {
                let dir = dir.join("acme");
                let contact = contact.context("contact is required for letsencrypt cert mode")?;
                tokio::fs::create_dir_all(&dir).await?;
                TlsAcceptor::letsencrypt(domain, &contact, prod, dir)?
            }
        })
    }
}

/// TLS Certificate Authority acceptor.
#[derive(Clone)]
pub enum TlsAcceptor {
    LetsEncrypt(AxumAcceptor),
    Manual(RustlsAcceptor),
}

impl<I: AsyncRead + AsyncWrite + Unpin + Send + 'static, S: Send + 'static> Accept<I, S>
    for TlsAcceptor
{
    type Stream = tokio_rustls::server::TlsStream<I>;
    type Service = S;
    type Future = BoxFuture<'static, io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        match self {
            Self::LetsEncrypt(a) => a.accept(stream, service).boxed(),
            Self::Manual(a) => a.accept(stream, service).boxed(),
        }
    }
}

impl TlsAcceptor {
    async fn self_signed(hostname: &str) -> Result<Self> {
        let tls_cert = rcgen::generate_simple_self_signed(vec![hostname.to_string()])?;
        let config = RustlsConfig::from_der(
            vec![tls_cert.serialize_der()?],
            tls_cert.serialize_private_key_der(),
        )
        .await?;
        let acceptor = RustlsAcceptor::new(config);
        Ok(Self::Manual(acceptor))
    }
    async fn manual(hostname: &str, dir: PathBuf) -> Result<Self> {
        let config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth();
        let keyname = escape_hostname(&hostname);
        let cert_path = dir.join(format!("{keyname}.crt"));
        let key_path = dir.join(format!("{keyname}.key"));

        println!("here");
        let (certs, secret_key) = tokio::task::spawn_blocking(move || {
            let certs = load_certs(cert_path)?;
            let key = load_secret_key(key_path)?;
            anyhow::Ok((certs, key))
        })
        .await??;
        println!("there");

        let config = config.with_single_cert(certs, secret_key)?;
        let config = Arc::new(config);
        // let acceptor = tokio_rustls::TlsAcceptor::from(config);
        let acceptor = RustlsAcceptor::new(RustlsConfig::from_config(config));
        Ok(Self::Manual(acceptor))
    }

    fn letsencrypt(
        hostname: &str,
        contact: &str,
        is_production: bool,
        dir: PathBuf,
    ) -> Result<Self> {
        let config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth();
        let mut state = AcmeConfig::new(vec![hostname])
            .contact([format!("mailto:{contact}")])
            .cache_option(Some(DirCache::new(dir)))
            .directory_lets_encrypt(is_production)
            .state();

        let config = config.with_cert_resolver(state.resolver());
        let acceptor = state.acceptor();

        tokio::spawn(
            async move {
                loop {
                    match state.next().await.unwrap() {
                        Ok(ok) => debug!("acme event: {:?}", ok),
                        Err(err) => error!("error: {:?}", err),
                    }
                }
            }
            .instrument(info_span!("acme")),
        );
        let config = Arc::new(config);
        let acceptor = AxumAcceptor::new(acceptor, config);
        Ok(Self::LetsEncrypt(acceptor))
    }
}

fn load_certs(filename: impl AsRef<Path>) -> Result<Vec<rustls::Certificate>> {
    let certfile = std::fs::File::open(filename).context("cannot open certificate file")?;
    let mut reader = std::io::BufReader::new(certfile);

    let certs = rustls_pemfile::certs(&mut reader)?
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect();

    Ok(certs)
}

fn load_secret_key(filename: impl AsRef<Path>) -> Result<rustls::PrivateKey> {
    let keyfile = std::fs::File::open(filename.as_ref()).context("cannot open secret key file")?;
    let mut reader = std::io::BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader).context("cannot parse secret key .pem file")? {
            Some(rustls_pemfile::Item::RSAKey(key)) => return Ok(rustls::PrivateKey(key)),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return Ok(rustls::PrivateKey(key)),
            Some(rustls_pemfile::Item::ECKey(key)) => return Ok(rustls::PrivateKey(key)),
            None => break,
            _ => {}
        }
    }

    bail!(
        "no keys found in {} (encrypted keys not supported)",
        filename.as_ref().display()
    );
}

fn escape_hostname(hostname: &str) -> Cow<'_, str> {
    let unsafe_hostname_characters = regex::Regex::new(r"[^a-zA-Z0-9-\.]").unwrap();
    unsafe_hostname_characters.replace_all(hostname, "")
}
