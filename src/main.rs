//
// Copyright (c) 2022 Nathan Fiedler
//
use actix_multipart::Multipart;
use actix_web::error::InternalError;
use actix_web::http::StatusCode;
use actix_web::{
    get, http::header, middleware, post, route, web, App, Error, HttpResponse, HttpServer,
    Responder,
};
use amemasu::BlobStore;
use futures::TryStreamExt;
use log::{debug, error, info};
use once_cell::sync::Lazy;
use std::env;
use std::io::Write;
use std::path::PathBuf;

#[cfg(test)]
static DEFAULT_BLOB_PATH: &str = "tmp/test/blobs";
#[cfg(not(test))]
static DEFAULT_BLOB_PATH: &str = "tmp/blobs";

static BLOB_PATH: Lazy<PathBuf> = Lazy::new(|| {
    let blob_path = env::var("BLOB_PATH").unwrap_or_else(|_| DEFAULT_BLOB_PATH.to_owned());
    PathBuf::from(&blob_path)
});

#[route("/blobs/{digest}", method = "GET", method = "HEAD")]
async fn get_blob(path: web::Path<(String,)>) -> impl Responder {
    let (digest,) = path.into_inner();
    let mut contents: Vec<u8> = Vec::new();
    let repository = BlobStore::new(&BLOB_PATH);
    match repository.fetch(&digest, &mut contents) {
        Ok(found) => {
            if found {
                HttpResponse::Ok()
                    .content_type("application/octet-stream")
                    .append_header((header::CONTENT_LENGTH, contents.len() as u64))
                    .body(contents)
            } else {
                HttpResponse::NotFound().finish()
            }
        }
        Err(err) => {
            error!("get_blob: {:?}", err);
            let reason = format!("{:?}", err);
            HttpResponse::InternalServerError().body(reason)
        }
    }
}

#[post("/blobs")]
async fn put_blob(mut payload: Multipart) -> Result<HttpResponse, Error> {
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
async fn del_blob(path: web::Path<(String,)>) -> impl Responder {
    let (digest,) = path.into_inner();
    let repository = BlobStore::new(&BLOB_PATH);
    match repository.delete(&digest) {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(err) => {
            error!("del_blob: {:?}", err);
            let reason = format!("{:?}", err);
            HttpResponse::InternalServerError().body(reason)
        }
    }
}

#[get("/status")]
async fn app_status() -> impl Responder {
    HttpResponse::Ok()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    env_logger::init();
    let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let port = env::var("PORT").unwrap_or_else(|_| "3000".to_owned());
    let addr = format!("{}:{}", host, port);
    info!("listening on http://{}/...", addr);
    HttpServer::new(|| {
        App::new()
            .wrap(middleware::Logger::default())
            .service(get_blob)
            .service(put_blob)
            .service(del_blob)
            .service(app_status)
    })
    .bind(addr)?
    .run()
    .await
}
