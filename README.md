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
