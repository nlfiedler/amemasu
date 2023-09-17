//
// Copyright (c) 2023 Nathan Fiedler
//
use actix_multipart::Multipart;
use actix_web::{
    dev::ServiceRequest,
    error::InternalError,
    get,
    http::{header, StatusCode},
    middleware, post, route, web, App, HttpResponse, HttpServer, Responder,
};
use actix_web_httpauth::{
    extractors::{
        bearer::{self, BearerAuth},
        AuthenticationError,
    },
    middleware::HttpAuthentication,
};
use amemasu::data::repositories::KeyRepositoryImpl;
use amemasu::data::sources::KeySetDataSourceImpl;
use amemasu::domain::entities::Checksum;
use amemasu::domain::usecases::{
    validate::{Params, ValidateToken},
    UseCase,
};
use amemasu::BlobStore;
use anyhow::Error;
use futures::TryStreamExt;
use log::{debug, error, info};
use once_cell::sync::Lazy;
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::env;
use std::fs::File;
use std::io::{BufReader, Write};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

#[cfg(test)]
static DEFAULT_BLOB_PATH: &str = "tmp/test/blobs";
#[cfg(not(test))]
static DEFAULT_BLOB_PATH: &str = "tmp/blobs";

static BLOB_PATH: Lazy<PathBuf> = Lazy::new(|| {
    let blob_path = env::var("BLOB_PATH").unwrap_or_else(|_| DEFAULT_BLOB_PATH.to_owned());
    PathBuf::from(&blob_path)
});

#[route(
    "/blobs/{digest}",
    method = "GET",
    method = "HEAD",
    wrap = "HttpAuthentication::bearer(read_validator)"
)]
async fn get_blob_auth(path: web::Path<(String,)>) -> Result<HttpResponse, actix_web::Error> {
    get_blob(path).await
}

#[route("/blobs/{digest}", method = "GET", method = "HEAD")]
async fn get_blob_open(path: web::Path<(String,)>) -> Result<HttpResponse, actix_web::Error> {
    get_blob(path).await
}

async fn get_blob(path: web::Path<(String,)>) -> Result<HttpResponse, actix_web::Error> {
    let (digest,) = path.into_inner();
    if Checksum::from_str(&digest).is_err() {
        return Ok(HttpResponse::BadRequest().body("invalid checksum"));
    }
    let result: Result<Vec<u8>, Error> = web::block(move || {
        let mut contents: Vec<u8> = Vec::new();
        let repository = BlobStore::new(&BLOB_PATH);
        repository.fetch(&digest, &mut contents)?;
        Ok(contents)
    })
    .await?;
    match result {
        Ok(contents) => {
            if contents.is_empty() {
                Ok(HttpResponse::NotFound().finish())
            } else {
                Ok(HttpResponse::Ok()
                    .content_type("application/octet-stream")
                    .append_header((header::CONTENT_LENGTH, contents.len() as u64))
                    .body(contents))
            }
        }
        Err(err) => {
            error!("get_blob: {:?}", err);
            let reason = format!("{:?}", err);
            Ok(HttpResponse::InternalServerError().body(reason))
        }
    }
}

#[post("/blobs", wrap = "HttpAuthentication::bearer(write_validator)")]
async fn put_blob_auth(payload: Multipart) -> Result<HttpResponse, actix_web::Error> {
    put_blob(payload).await
}

#[post("/blobs")]
async fn put_blob_open(payload: Multipart) -> Result<HttpResponse, actix_web::Error> {
    put_blob(payload).await
}

async fn put_blob(mut payload: Multipart) -> Result<HttpResponse, actix_web::Error> {
    while let Ok(Some(mut field)) = payload.try_next().await {
        let disposition = field.content_disposition();
        let hash_digest = disposition
            .get_filename()
            .ok_or(actix_web::error::ContentTypeError::ParseError)?
            .to_owned();
        let mut bytes: Vec<u8> = Vec::new();
        while let Some(chunk) = field.try_next().await? {
            bytes = web::block(move || bytes.write_all(&chunk).map(|_| bytes)).await??;
        }
        let result = web::block(move || {
            let repository = BlobStore::new(&BLOB_PATH);
            let result = repository.store(&hash_digest, &mut bytes.as_slice());
            debug!("stored blob with digest {}", hash_digest);
            result
        })
        .await?;
        if let Err(err) = result {
            let reason = format!("{:?}", err);
            let error = InternalError::new(reason, StatusCode::INTERNAL_SERVER_ERROR);
            return Err(error.into());
        }
    }
    Ok(HttpResponse::Ok().finish())
}

#[route(
    "/blobs/{digest}",
    method = "DELETE",
    wrap = "HttpAuthentication::bearer(write_validator)"
)]
async fn del_blob_auth(path: web::Path<(String,)>) -> Result<HttpResponse, actix_web::Error> {
    del_blob(path).await
}

#[route("/blobs/{digest}", method = "DELETE")]
async fn del_blob_open(path: web::Path<(String,)>) -> Result<HttpResponse, actix_web::Error> {
    del_blob(path).await
}

async fn del_blob(path: web::Path<(String,)>) -> Result<HttpResponse, actix_web::Error> {
    let (digest,) = path.into_inner();
    if Checksum::from_str(&digest).is_err() {
        return Ok(HttpResponse::BadRequest().body("invalid checksum"));
    }
    let result = web::block(move || {
        let repository = BlobStore::new(&BLOB_PATH);
        repository.delete(&digest)
    })
    .await?;
    match result {
        Ok(_) => Ok(HttpResponse::Ok().finish()),
        Err(err) => {
            error!("del_blob: {:?}", err);
            let reason = format!("{:?}", err);
            Ok(HttpResponse::InternalServerError().body(reason))
        }
    }
}

#[get("/status")]
async fn app_status() -> impl Responder {
    HttpResponse::Ok()
}

// ensure caller has read or write access
async fn read_validator(
    req: ServiceRequest,
    credentials: BearerAuth,
) -> Result<ServiceRequest, (actix_web::Error, ServiceRequest)> {
    // write access grants read access
    purpose_validator(req, credentials, &["read", "write"]).await
}

// ensure caller has write access
async fn write_validator(
    req: ServiceRequest,
    credentials: BearerAuth,
) -> Result<ServiceRequest, (actix_web::Error, ServiceRequest)> {
    purpose_validator(req, credentials, &["write"]).await
}

// Call on the issuer to retrieve the JWKS, then validate the given bearer token
// to ensure the configured issuer signed it. Additionally, check that the
// claims include a `purpose` and that its value matches one of those given.
//
// But only do this if the ISSUER_URI environment variable is configured.
async fn purpose_validator(
    req: ServiceRequest,
    credentials: BearerAuth,
    purpose: &[&str],
) -> Result<ServiceRequest, (actix_web::Error, ServiceRequest)> {
    if let Ok(issuer_uri) = env::var("ISSUER_URI") {
        let data_source = KeySetDataSourceImpl::new(issuer_uri.clone());
        let repo = KeyRepositoryImpl::new(Arc::new(data_source));
        let usecase = ValidateToken::new(Arc::new(repo));
        let jwks_id = env::var("JWKS_KEYID").ok();
        let audience = env::var("AUDIENCE").ok();
        let params = Params::new(credentials.token().into(), jwks_id, audience);
        let config = req
            .app_data::<bearer::Config>()
            .cloned()
            .unwrap_or_default()
            .scope("blobs");
        match usecase.call(params) {
            Ok(Some(actual)) => {
                if purpose.iter().any(|p| *p == actual) {
                    Ok(req)
                } else {
                    Err((AuthenticationError::from(config).into(), req))
                }
            }
            Ok(None) => Err((AuthenticationError::from(config).into(), req)),
            Err(err) => {
                error!("ok_validator: {:?}", err);
                let error = actix_web_httpauth::extractors::bearer::Error::InvalidRequest;
                Err((
                    AuthenticationError::from(config).with_error(error).into(),
                    req,
                ))
            }
        }
    } else {
        Ok(req)
    }
}

fn load_rustls_config() -> Result<rustls::ServerConfig, Error> {
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth();
    let cert_path = env::var("CERT_FILE").unwrap_or_else(|_| "certs/cert.pem".to_owned());
    let key_path = env::var("KEY_FILE").unwrap_or_else(|_| "certs/key.pem".to_owned());
    let cert_file = &mut BufReader::new(File::open(cert_path)?);
    let key_file = &mut BufReader::new(File::open(key_path)?);
    let cert_chain = certs(cert_file)?.into_iter().map(Certificate).collect();
    let mut keys: Vec<PrivateKey> = pkcs8_private_keys(key_file)?
        .into_iter()
        .map(PrivateKey)
        .collect();
    if keys.is_empty() {
        eprintln!("error: could not find PKCS 8 private keys");
        std::process::exit(1);
    }
    Ok(config.with_single_cert(cert_chain, keys.remove(0))?)
}

fn config(cfg: &mut web::ServiceConfig) {
    // authenticated routes are enabled if ISSUER_URI is configured
    if env::var("ISSUER_URI").is_ok() {
        cfg.service(get_blob_auth)
            .service(put_blob_auth)
            .service(del_blob_auth)
            .service(app_status);
    } else {
        cfg.service(get_blob_open)
            .service(put_blob_open)
            .service(del_blob_open)
            .service(app_status);
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    env_logger::init();
    let rustls_config =
        load_rustls_config().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let port = env::var("PORT").unwrap_or_else(|_| "3000".to_owned());
    let addr = format!("{}:{}", host, port);
    info!("listening on https://{}/...", addr);
    HttpServer::new(|| {
        App::new()
            .wrap(middleware::Logger::default())
            .configure(config)
    })
    .bind_rustls(addr, rustls_config)?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{http, test, web::Buf};
    use anyhow::anyhow;
    use hyper::{Body, Client, Method, Request};
    use hyper_tls::HttpsConnector;
    use serde_json::Value;

    #[actix_web::test]
    async fn test_app_status_ok() {
        let app = test::init_service(App::new().service(app_status)).await;
        let req = test::TestRequest::get().uri("/status").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
    }

    #[actix_web::test]
    async fn test_get_blob_bad_checksum() {
        let app = test::init_service(App::new().service(get_blob_open)).await;
        let req = test::TestRequest::get().uri("/blobs/hal9000").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_web::test]
    async fn test_get_blob_not_found() {
        let app = test::init_service(App::new().service(get_blob_open)).await;
        let req = test::TestRequest::get()
            .uri("/blobs/sha1-cafebabe")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
    }

    #[actix_web::test]
    async fn test_get_blob_auth() {
        let app = test::init_service(App::new().service(get_blob_auth)).await;
        let req = test::TestRequest::get()
            .uri("/blobs/sha1-cafebabe")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn test_del_blob_bad_checksum() {
        let app = test::init_service(App::new().service(del_blob_open)).await;
        let req = test::TestRequest::delete()
            .uri("/blobs/hal9000")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_web::test]
    async fn test_del_blob_not_found_is_ok() {
        let app = test::init_service(App::new().service(del_blob_open)).await;
        let req = test::TestRequest::delete()
            .uri("/blobs/sha1-cafebabe")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
    }

    #[actix_web::test]
    async fn test_del_blob_auth() {
        let app = test::init_service(App::new().service(del_blob_auth)).await;
        let req = test::TestRequest::delete()
            .uri("/blobs/sha1-cafebabe")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn test_put_blob_auth() {
        let app = test::init_service(App::new().service(put_blob_auth)).await;
        let req = test::TestRequest::post().uri("/blobs").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn test_workflow_open() {
        let boundary = "----WebKitFormBoundary0gYa4NfETro6nMot";
        let mut app = test::init_service(App::new().service(put_blob_open)).await;
        let ct_header = format!("multipart/form-data; boundary={}", boundary);
        let filename = "./LICENSE";
        let raw_file = std::fs::read(filename).unwrap();
        #[cfg(target_family = "unix")]
        let license_sha1 = "49d32dbed9a10e78b6c0908a41f89437451879c4";
        #[cfg(target_family = "windows")]
        let license_sha1 = "84D3ACE37C8B34DCC87C2BDCAE72D764339786C7";
        let mut payload: Vec<u8> = Vec::new();
        let mut boundary_before = String::from("--");
        boundary_before.push_str(boundary);
        boundary_before.push_str("\r\nContent-Disposition: form-data;");
        let filename = format!(r#" name="foo"; filename="sha1-{}""#, &license_sha1);
        boundary_before.push_str(&filename);
        boundary_before.push_str("\r\nContent-Type: text/plain\r\n\r\n");
        payload.write(boundary_before.as_bytes()).unwrap();
        payload.write(&raw_file).unwrap();
        let mut boundary_after = String::from("\r\n--");
        boundary_after.push_str(boundary);
        boundary_after.push_str("--\r\n");
        payload.write(boundary_after.as_bytes()).unwrap();
        let req = test::TestRequest::post()
            .uri("/blobs")
            .append_header((header::CONTENT_TYPE, ct_header))
            .append_header((header::CONTENT_LENGTH, payload.len()))
            .set_payload(payload)
            .to_request();
        let resp = test::call_service(&mut app, req).await;
        assert!(resp.status().is_success());

        #[cfg(target_family = "unix")]
        let blob_path = "/blobs/sha1-49d32dbed9a10e78b6c0908a41f89437451879c4";
        #[cfg(target_family = "windows")]
        let blob_path = "/blobs/sha1-84d3ace37c8b34dcc87c2bdcae72d764339786c7";

        // test retrieval
        let app = test::init_service(App::new().service(get_blob_open)).await;
        let req = test::TestRequest::get().uri(blob_path).to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        // delete the blob
        let app = test::init_service(App::new().service(del_blob_open)).await;
        let req = test::TestRequest::delete().uri(blob_path).to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
    }

    async fn fetch_access_token(
        base_uri: &str,
        username: &str,
        password: &str,
    ) -> Result<String, Error> {
        let https = HttpsConnector::new();
        let client = Client::builder().build::<_, hyper::Body>(https);

        // retrieve an access token
        let tokens_uri = format!("{}/tokens", base_uri);
        let req = Request::builder()
            .method(Method::POST)
            .uri(&tokens_uri)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(format!(
                r#"grant_type=password&username={}&password={}"#,
                username, password
            )))?;
        let resp = client.request(req).await?;
        if resp.status() != 200 {
            let msg = "tokens request failed";
            return Err(anyhow!(msg));
        }
        let body = hyper::body::to_bytes(resp.into_body()).await?;
        let buf = body.reader();
        let raw_value: Value = serde_json::from_reader(buf)?;
        let token = raw_value.as_object().unwrap();
        let access_token = token["access_token"].as_str().unwrap();
        Ok(access_token.to_owned())
    }

    #[actix_web::test]
    async fn test_put_blob_write_access() {
        if let Ok(issuer_uri) = env::var("ISSUER_URI") {
            // user johndoe has read access, delete request will fail
            let access_token = fetch_access_token(&issuer_uri, "johndoe", "tiger2")
                .await
                .unwrap();
            let bearer_header = format!("Bearer {}", access_token);
            let app = test::init_service(App::new().service(del_blob_auth)).await;
            let req = test::TestRequest::delete()
                .uri("/blobs/sha1-cafebabe")
                .append_header((header::AUTHORIZATION, bearer_header.clone()))
                .to_request();
            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);

            // reading a blob is okay with read access
            let app = test::init_service(App::new().service(get_blob_auth)).await;
            let req = test::TestRequest::get()
                .uri("/blobs/sha1-cafebabe")
                .append_header((header::AUTHORIZATION, bearer_header.clone()))
                .to_request();
            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
        }
    }

    #[actix_web::test]
    async fn test_workflow_with_auth() {
        if let Ok(issuer_uri) = env::var("ISSUER_URI") {
            let access_token = fetch_access_token(&issuer_uri, "janedoe", "tiger1")
                .await
                .unwrap();
            let bearer_header = format!("Bearer {}", access_token);
            let boundary = "----WebKitFormBoundary0gYa4NfETro6nMot";
            let mut app = test::init_service(App::new().service(put_blob_auth)).await;
            let ct_header = format!("multipart/form-data; boundary={}", boundary);
            let filename = "./LICENSE";
            let raw_file = std::fs::read(filename).unwrap();
            #[cfg(target_family = "unix")]
            let license_sha1 = "49d32dbed9a10e78b6c0908a41f89437451879c4";
            #[cfg(target_family = "windows")]
            let license_sha1 = "84D3ACE37C8B34DCC87C2BDCAE72D764339786C7";
            let mut payload: Vec<u8> = Vec::new();
            let mut boundary_before = String::from("--");
            boundary_before.push_str(boundary);
            boundary_before.push_str("\r\nContent-Disposition: form-data;");
            let filename = format!(r#" name="foo"; filename="sha1-{}""#, &license_sha1);
            boundary_before.push_str(&filename);
            boundary_before.push_str("\r\nContent-Type: text/plain\r\n\r\n");
            payload.write(boundary_before.as_bytes()).unwrap();
            payload.write(&raw_file).unwrap();
            let mut boundary_after = String::from("\r\n--");
            boundary_after.push_str(boundary);
            boundary_after.push_str("--\r\n");
            payload.write(boundary_after.as_bytes()).unwrap();
            let req = test::TestRequest::post()
                .uri("/blobs")
                .append_header((header::CONTENT_TYPE, ct_header))
                .append_header((header::CONTENT_LENGTH, payload.len()))
                .append_header((header::AUTHORIZATION, bearer_header.clone()))
                .set_payload(payload)
                .to_request();
            let resp = test::call_service(&mut app, req).await;
            assert!(resp.status().is_success());

            #[cfg(target_family = "unix")]
            let blob_path = "/blobs/sha1-49d32dbed9a10e78b6c0908a41f89437451879c4";
            #[cfg(target_family = "windows")]
            let blob_path = "/blobs/sha1-84d3ace37c8b34dcc87c2bdcae72d764339786c7";

            // test retrieval
            let app = test::init_service(App::new().service(get_blob_auth)).await;
            let req = test::TestRequest::get()
                .uri(blob_path)
                .append_header((header::AUTHORIZATION, bearer_header.clone()))
                .to_request();
            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), http::StatusCode::OK);

            // delete the blob
            let app = test::init_service(App::new().service(del_blob_auth)).await;
            let req = test::TestRequest::delete()
                .uri(blob_path)
                .append_header((header::AUTHORIZATION, bearer_header.clone()))
                .to_request();
            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), http::StatusCode::OK);
        }
    }
}
