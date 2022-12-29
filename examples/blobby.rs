//
// Copyright (c) 2022 Nathan Fiedler
//
use amemasu::BlobStore;
use anyhow::Error;
use clap::Parser;
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::Path;

#[derive(Parser)]
#[command(name = "blobby")]
#[command(bin_name = "blobby")]
enum Blobby {
    /// Store the given file in blob repository.
    Put(Put),
    /// Retrieve a blob from the repository.
    Get(Get),
    /// Remove a blob from the repository.
    Del(Del),
}

#[derive(clap::Args)]
struct Put {
    /// Path of file to be stored in repository.
    #[arg(long, required = true)]
    file: Option<std::path::PathBuf>,
}

#[derive(clap::Args)]
struct Get {
    /// Digest of the blob to be retrieved.
    #[arg(long, required = true)]
    hash: Option<String>,
    /// Path to which blob contents will be written.
    #[arg(long, required = true)]
    file: Option<std::path::PathBuf>,
}

#[derive(clap::Args)]
struct Del {
    /// Digest of the blob to be removed.
    #[arg(long, required = true)]
    hash: Option<String>,
}

fn main() {
    let repo = BlobStore::new(Path::new("tmp/blobs"));
    match Blobby::parse() {
        Blobby::Put(args) => {
            let infile = args.file.unwrap();
            match put_blob(&infile, &repo) {
                Ok(digest) => {
                    println!("stored blob with digest: {}", digest);
                }
                Err(err) => {
                    println!("error: {:?}", err);
                }
            }
        }
        Blobby::Get(args) => {
            let digest = args.hash.unwrap();
            let outfile = args.file.unwrap();
            if let Err(err) = get_blob(&digest, &outfile, &repo) {
                println!("error: {:?}", err);
            }
        }
        Blobby::Del(args) => {
            let digest = args.hash.unwrap();
            match repo.delete(&digest) {
                Ok(_) => {
                    println!("deleted blob with digest: {}", digest)
                }
                Err(err) => {
                    println!("error: {:?}", err);
                }
            }
        }
    }
}

fn put_blob(infile: &Path, repo: &BlobStore) -> Result<String, Error> {
    let mut source = fs::File::open(infile)?;
    let mut hasher = Sha256::new();
    io::copy(&mut source, &mut hasher)?;
    let hash = hasher.finalize();
    let digest = format!("sha256-{:x}", hash);
    source = fs::File::open(infile)?;
    repo.store(&digest, &mut source)?;
    Ok(digest)
}

fn get_blob(digest: &str, outfile: &Path, repo: &BlobStore) -> Result<(), Error> {
    let mut sink = fs::File::create(outfile)?;
    let found = repo.fetch(digest, &mut sink)?;
    if found {
        println!("retrieved blob with digest: {}", digest);
    } else {
        println!("blob not found in repository");
    }
    Ok(())
}
