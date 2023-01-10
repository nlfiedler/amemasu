# Amemasu

This crate implements a simple blob store. Clients will compute the hash digest and provide it along with the file content. The blob store will verify the digest both on write and later when retrieving the blob using the same digest. Optional authorization can be enabled in which JSON Web Tokens (JWT, [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519)) are received and verified against an OpenID provider's JSON Web Key Set (JWKS, [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517)).

## Requirements

* [Rust](https://www.rust-lang.org) stable (2021 edition)

## Building and Testing

```shell
$ cargo build
$ cargo test
```

### Testing authorization support

Some of the test cases involve making a request for the configuration and key set from an OpenID provider, which are only enabled if the `ISSUER_URI` environment variable is set. Such a server is readily available via the `jwt-test-server` docker image ([git repo](https://github.com/nlfiedler/jwt-test-server)). In the example below, the `http://192.168.1.3` address refers to the docker host. Note that the `hyper` crate used by this application will not accept self-signed certificates, so starting the fake provider with `http` is necessary.

```shell
docker run -d -p 3000:3000 -e PROTOCOL=http -e BASE_URI=http://192.168.1.3:3000 --name jwt-test-server nlfiedler/jwt-test-server:latest
```

Running the tests would then look like:

```shell
env ISSUER_URI=http://192.168.1.3:3000 cargo test
```

## Example Usage

An example of using this crate as a library can be found in the `examples` directory of the source repository, which demonstrates storing and retrieving blobs.

```shell
$ cargo run --example blobby -- put --file README.md
   Compiling amemasu v0.1.0 (/Users/nfiedler/projects/amemasu)
    Finished dev [unoptimized + debuginfo] target(s) in 0.37s
     Running `target/debug/examples/blobby put --file README.md`
stored blob with digest: sha256-b8d6810ab4b5cd71a96c0123ec2da129f35347ded0a69650be8c71eb5c2f963a
```

### Storing a blob

```rust
let repo = BlobStore::new(Path::new("blobs"));
let mut source = fs::File::open("blobby.txt")?;
let mut hasher = Sha1::new();
io::copy(&mut source, &mut hasher)?;
let hash = hasher.finalize();
let digest = format!("sha1-{:x}", hash);
source = fs::File::open(infile)?;
repo.store(&digest, &mut source)?;
```

### Fetching a blob

```rust
let repo = BlobStore::new(Path::new("blobs"));
let mut sink = fs::File::create("blobby.txt")?;
let digest: String = "sha1-6584933d1efb012a9f61a48b1922b86c3708a6c2".into();
let found = repo.fetch(digest, &mut sink)?;
if found {
    println!("retrieved blob with digest: {}", digest);
} else {
    println!("blob not found in repository");
}
```

### Deleting a blob

```rust
let repo = BlobStore::new(Path::new("blobs"));
let digest: String = "sha1-6584933d1efb012a9f61a48b1922b86c3708a6c2".into();
repo.delete(&digest)?;
```

## Running as a server

The binary form of `amemasu` will start an HTTP/S server. Depending on the configuration, it may require authorization for any `/blob` requests.

### Configuring

By default the server will bind to the local address and listen on port 3000. No authorization is required for any of the operations, unless `ISSUER_URI` is set.

To modify the configuration, set any of the environment variables shown in the table below. The server will look for a file named `.env` and evaluate it using the `dotenv` crate. Any `name=value` pairs defined in that file will result in setting the named environment variable with the given value. Comment lines, which start with `#`, as well as blank lines, will be ignored.

| Name | Description | Default Value |
| ---- | ----------- | ------------- |
| `HOST` | address on which to bind | `127.0.0.1` |
| `PORT` | port on which to listen | `3000` |
| `RUST_LOG` | logging level such as `debug` or `info` | `error` (see [env_logger](https://docs.rs/env_logger/latest/env_logger/)) |
| `BLOB_PATH` | path to directory for storing blobs | `tmp/blobs` |
| `CERT_FILE` | path of PEM-encoded file containing public certificate | `certs/cert.pem` |
| `KEY_FILE` | path of PEM-encoded file containing private key | `certs/key.pem` |
| `ISSUER_URI` | URI of the OpenID provider | _none_ |
| `AUDIENCE` | optional `aud` value by which to restrict access | _none_ |
| `JWKS_KEYID` | optional `kid` value for selecting allowed keys | _none_ |

### Authorization

Normally the server will not require any authorization to perform `/blob` operations. However, if the `ISSUER_URI` environment variable is defined, then all `/blobs` requests will require a JSON Web Token via the `Authorization` HTTP header (see [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750)). The token will be validated against the key set served by the provider; additionally the token payload must have a `purpose` claim that is either `read` or `write`. Blob operations that make modifications require `write` access (`PUT /blobs` and `DELETE /blobs`) while the read operation (`GET /blobs`) will accept either `read` or `write` access.

At this time, the only supported key encryption algorithm is `RS256`, meaning that a public/private key pair must be used to sign and validate the token.

In addition to validating the token against the key set, an audience value can be provided via the `AUDIENCE` environment variable, further restricting access to tokens that have a matching `aud` claim in the token payload.

By default, the server will take the first key in the key set to validate the token, but this can be restricted to a specific key by setting the `JWKS_KEYID` environment variable. Note that at this time, the server does not try all of the keys offered in the set, nor does it consider the `kid` from the token header.

### Certificates

The default self-signed TLS certificates in the `certs` directory, `cert.pem` and `key.pem`, were created using the [mkcert](https://github.com/FiloSottile/mkcert) utility, although `openssl` would also work. The advantage of `mkcert` is that it will install certificate authority certs to validate the certs created with `mkcert`.

### Storing a blob

In the following example, `localfile` is the actual path of the file to be stored in the blob repository, and `digest` is a hash digest in hexadecimal form, with an algorithm prefix (e.g. `sha1-df5d75a08b363294bbfe80dbbbe3542f89aa8dab`).

```shell
curl -F "file=@localfile;filename=digest" https://localhost:3000/blobs
```

### Fetching a blob

In the following example, `digest` is a hash digest of the blob in hexadecimal form, with an algorithm prefix (e.g. `sha1-df5d75a08b363294bbfe80dbbbe3542f89aa8dab`).

```shell
curl -k https://localhost:3000/blobs/digest
```

### Deleting a blob

In the following example, `digest` is a hash digest of the blob in hexadecimal form, with an algorithm prefix (e.g. `sha1-df5d75a08b363294bbfe80dbbbe3542f89aa8dab`).

```shell
curl -k -X DELETE https://localhost:3000/blobs/digest
```
