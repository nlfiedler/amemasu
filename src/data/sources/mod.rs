//
// Copyright (c) 2023 Nathan Fiedler
//
use anyhow::{anyhow, Error};
use hyper::{body::Buf, Client};
use hyper_tls::HttpsConnector;
#[cfg(test)]
use mockall::automock;

/// Data source for unparsed JSON Web Key Set data.
#[cfg_attr(test, automock)]
pub trait KeySetDataSource: Send + Sync {
    /// Retrieve the unparsed key set data.
    fn get_key_set(&self) -> Result<String, Error>;
}

/// Basic implementation that uses HTTP to retrieve the raw data.
pub struct KeySetDataSourceImpl {
    issuer: String,
}

impl KeySetDataSourceImpl {
    pub fn new(issuer: String) -> Self {
        Self {
            issuer: build_issuer_uri(&issuer),
        }
    }
}

impl KeySetDataSource for KeySetDataSourceImpl {
    fn get_key_set(&self) -> Result<String, Error> {
        // Bridge the sync/async chasm by spawning a thread to spawn a runtime
        // that will manage the future for us.
        let (tx, rx) = std::sync::mpsc::channel::<Result<String, Error>>();
        let issuer = self.issuer.to_owned();
        std::thread::spawn(move || {
            tx.send(get_key_set_sync(&issuer)).unwrap();
        });
        rx.recv()?
    }
}

async fn get_key_set(issuer: &str) -> Result<String, Error> {
    // Creating a client every time may seem wasteful, but we also just spawned
    // a thread and created a tokio runtime just to bridge the sync/async chasm.
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);
    let uri = issuer.parse()?;
    let resp = client.get(uri).await?;
    if resp.status() != 200 {
        return Err(anyhow!("jwks request failed: {}", resp.status()));
    }
    let body = hyper::body::to_bytes(resp.into_body()).await?;
    let buf = body.reader();
    let raw_data = std::io::read_to_string(buf)?;
    Ok(raw_data)
}

fn get_key_set_sync(issuer: &str) -> Result<String, Error> {
    block_on(get_key_set(issuer)).and_then(std::convert::identity)
}

/// Run the given future on a newly created single-threaded runtime if possible,
/// otherwise raise an error if this thread already has a runtime.
fn block_on<F: core::future::Future>(future: F) -> Result<F::Output, Error> {
    if let Ok(_handle) = tokio::runtime::Handle::try_current() {
        Err(anyhow!("cannot call block_on inside a runtime"))
    } else {
        // Build the simplest and lightest runtime we can, while still enabling
        // us to wait for this future (and everything it spawns) to complete
        // synchronously. Must enable the io and time features otherwise the
        // runtime does not really start.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        Ok(runtime.block_on(future))
    }
}

fn build_issuer_uri(issuer: &str) -> String {
    if issuer.ends_with("/.well-known/jwks.json") {
        issuer.to_owned()
    } else if issuer.ends_with("/") {
        issuer.to_owned() + ".well-known/jwks.json"
    } else {
        issuer.to_owned() + "/.well-known/jwks.json"
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_key_set_err() {
        let uri = "http://127.0.0.1:4321";
        let sut = KeySetDataSourceImpl::new(uri.into());
        let result = sut.get_key_set();
        assert!(result.is_err());
    }

    #[test]
    fn test_get_key_set_ok() {
        // set up the environment and remote connection
        dotenv::dotenv().ok();
        let uri_var = std::env::var("ISSUER_URI");
        if let Ok(issuer_uri) = uri_var {
            let sut = KeySetDataSourceImpl::new(issuer_uri.clone());
            let result = sut.get_key_set();
            assert!(result.is_ok());
            let raw_data = result.unwrap();
            assert!(raw_data.contains("RS256"));
        }
    }

    #[test]
    fn test_build_issuer_uri() {
        assert_eq!(
            build_issuer_uri("localhost"),
            "localhost/.well-known/jwks.json"
        );
        assert_eq!(
            build_issuer_uri("localhost/"),
            "localhost/.well-known/jwks.json"
        );
        assert_eq!(
            build_issuer_uri("localhost/.well-known/jwks.json"),
            "localhost/.well-known/jwks.json"
        );
    }
}
