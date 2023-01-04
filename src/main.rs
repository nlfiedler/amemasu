//
// Copyright (c) 2022 Nathan Fiedler
//
use actix_multipart::Multipart;
use actix_web::error::InternalError;
use actix_web::http::StatusCode;
use actix_web::{
    get, http::header, middleware, post, route, web, App, HttpResponse, HttpServer, Responder,
};
use amemasu::domain::entities::Checksum;
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

#[cfg(test)]
static DEFAULT_BLOB_PATH: &str = "tmp/test/blobs";
#[cfg(not(test))]
static DEFAULT_BLOB_PATH: &str = "tmp/blobs";

static BLOB_PATH: Lazy<PathBuf> = Lazy::new(|| {
    let blob_path = env::var("BLOB_PATH").unwrap_or_else(|_| DEFAULT_BLOB_PATH.to_owned());
    PathBuf::from(&blob_path)
});

#[route("/blobs/{digest}", method = "GET", method = "HEAD")]
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

#[post("/blobs")]
async fn put_blob(mut payload: Multipart) -> Result<HttpResponse, actix_web::Error> {
    while let Ok(Some(mut field)) = payload.try_next().await {
        let disposition = field.content_disposition();
        let hash_digest = disposition
            .get_filename()
            .ok_or_else(|| actix_web::error::ContentTypeError::ParseError)?
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

#[route("/blobs/{digest}", method = "DELETE")]
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
            .service(get_blob)
            .service(put_blob)
            .service(del_blob)
            .service(app_status)
    })
    .bind_rustls(addr, rustls_config)?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{http, test};

    #[actix_web::test]
    async fn test_app_status_ok() {
        let app = test::init_service(App::new().service(app_status)).await;
        let req = test::TestRequest::get().uri("/status").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
    }

    #[actix_web::test]
    async fn test_get_blob_bad_checksum() {
        let app = test::init_service(App::new().service(get_blob)).await;
        let req = test::TestRequest::get().uri("/blobs/hal9000").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_web::test]
    async fn test_get_blob_not_found() {
        let app = test::init_service(App::new().service(get_blob)).await;
        let req = test::TestRequest::get()
            .uri("/blobs/sha1-cafebabe")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
    }

    #[actix_web::test]
    async fn test_del_blob_bad_checksum() {
        let app = test::init_service(App::new().service(del_blob)).await;
        let req = test::TestRequest::delete()
            .uri("/blobs/hal9000")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_web::test]
    async fn test_del_blob_not_found_is_ok() {
        let app = test::init_service(App::new().service(del_blob)).await;
        let req = test::TestRequest::delete()
            .uri("/blobs/sha1-cafebabe")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
    }

    #[actix_web::test]
    async fn test_put_blob_ok() {
        let boundary = "----WebKitFormBoundary0gYa4NfETro6nMot";
        let mut app = test::init_service(App::new().service(put_blob)).await;
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
        let app = test::init_service(App::new().service(get_blob)).await;
        let req = test::TestRequest::get().uri(blob_path).to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        // delete the blob
        let app = test::init_service(App::new().service(del_blob)).await;
        let req = test::TestRequest::delete().uri(blob_path).to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
    }
}
