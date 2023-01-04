# Amemasu

This crate implements a simple blob store. Clients will compute the hash digest and provide it along with the file content. The store will verify the digest both on write and later when retrieving the blob using the same digest.

## Requirements

* [Rust](https://www.rust-lang.org) stable (2021 edition)

## Building and Testing

```shell
$ cargo clean
$ cargo build
$ cargo test
```

## Example Usage

An example can be found in the `examples` directory of the source repository, which demonstrates storing and retrieving blobs.

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
let mut hasher = Sha256::new();
io::copy(&mut source, &mut hasher)?;
let hash = hasher.finalize();
let digest = format!("sha256-{:x}", hash);
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

The binary form of `amemasu` will start an web server serving requests over HTTPS.

### Configuring

By default the server will bind to the local address and listen on port 3000.

To modify the configuration, set any of the environment variables shown in the table below. The server will look for a file named `.env` and evaluate it using the `dotenv` crate. Any `name=value` pairs defined in that file will result in setting the named environment variable with the given value. Comment lines, which start with `#`, and blank lines, will be ignored.

| Name | Description | Default Value |
| ---- | ----------- | ------------- |
| `HOST` | address on which to bind | `127.0.0.1` |
| `PORT` | port on which to listen | `3000` |
| `RUST_LOG` | logging level such as `debug` or `info` | `error` (see [env_logger](https://docs.rs/env_logger/latest/env_logger/)) |
| `BLOB_PATH` | path to directory for storing blobs | `tmp/blobs` |
| `CERT_FILE` | path of PEM-encoded file containing public certificate | `certs/cert.pem` |
| `KEY_FILE` | path of PEM-encoded file containing private key | `certs/key.pem` |

### Certificates

The default self-signed TLS certificates in the `certs` directory, `cert.pem` and `key.pem`, where created using the [mkcert](https://github.com/FiloSottile/mkcert) utility, although `openssl` would also work. The advantage of `mkcert` is that it will install certificate authority certs to validate the certs created with `mkcert`.

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
