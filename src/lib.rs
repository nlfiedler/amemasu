//
// Copyright (c) 2022 Nathan Fiedler
//
use crate::data::repositories::BlobRepositoryImpl;
use crate::domain::entities::{Blob, Checksum};
use crate::domain::repositories::BlobRepository;
use crate::domain::usecases::UseCase;
use anyhow::Error;
use std::io::{Read, Write};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

pub mod data;
pub mod domain;

///
/// A blob store that writes blobs into a given directory path.
///
/// The blob digests will be verified on store and fetch. The digests must have
/// a prefix that is one of "sha1-", "sha224-", or "sha256-" as those are the
/// supported algorithms.
///
#[derive(Clone)]
pub struct BlobStore {
    repository: Arc<dyn BlobRepository>,
}

impl BlobStore {
    /// Construct a new blob store that will save blobs to the given path.
    pub fn new(basepath: &Path) -> Self {
        let repo = BlobRepositoryImpl::new(basepath);
        Self {
            repository: Arc::new(repo),
        }
    }

    /// Store the blob given by `source` with the corresponding `digest`.
    pub fn store(&self, digest: &str, source: &mut dyn Read) -> Result<(), Error> {
        use crate::domain::usecases::store::{Params, StoreBlob};
        let checksum: Checksum = FromStr::from_str(digest)?;
        let mut contents = Vec::new();
        source.read_to_end(&mut contents)?;
        let blobby = Blob::new(checksum, contents);
        let usecase = StoreBlob::new(self.repository.clone());
        let params = Params::new(blobby);
        usecase.call(params)
    }

    /// Retrieve the blob identified by `digest` into the given `sink`.
    pub fn fetch(&self, digest: &str, sink: &mut dyn Write) -> Result<bool, Error> {
        use crate::domain::usecases::fetch::{FetchBlob, Params};
        let checksum: Checksum = FromStr::from_str(digest)?;
        let usecase = FetchBlob::new(self.repository.clone());
        let params = Params::new(checksum);
        let blobby = usecase.call(params)?;
        if let Some(contents) = blobby {
            sink.write_all(contents.data.as_ref())?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Permanently delete the blog identified by `digest`.
    pub fn delete(&self, digest: &str) -> Result<(), Error> {
        use crate::domain::usecases::delete::{DeleteBlob, Params};
        let checksum: Checksum = FromStr::from_str(digest)?;
        let usecase = DeleteBlob::new(self.repository.clone());
        let params = Params::new(checksum);
        usecase.call(params)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use once_cell::sync::Lazy;
    use tempfile::tempdir;

    static MARY_DATA: Lazy<Vec<u8>> = Lazy::new(|| {
        vec![
            0x6d, 0x61, 0x72, 0x79, 0x20, 0x68, 0x61, 0x64, 0x20, 0x61, 0x20, 0x6c, 0x69, 0x74,
            0x74, 0x6c, 0x65, 0x20, 0x6c, 0x61, 0x6d, 0x62, 0x0a,
        ]
    });

    #[test]
    fn test_workflow() {
        // set up
        let tmpdir = tempdir().unwrap();
        let basepath = tmpdir.path().join("blobs");
        let blob_store = BlobStore::new(basepath.as_path());
        let digest = "sha1-9873bd2820da36edcc4f52e23b6b2e047257a4cd";

        // store
        let contents = MARY_DATA.clone();
        let result = blob_store.store(digest, &mut contents.as_slice());
        assert!(result.is_ok());
        let mut dest_path = basepath.clone();
        let id_path = "98/73bd2820da36edcc4f52e23b6b2e047257a4cd";
        dest_path.push(id_path);
        assert!(dest_path.exists());

        // fetch (missing)
        let mut contents: Vec<u8> = Vec::new();
        let result = blob_store.fetch("sha1-cafebabe", &mut contents);
        assert!(result.is_ok());
        assert!(!result.unwrap());

        // fetch (found)
        let mut contents: Vec<u8> = Vec::new();
        let result = blob_store.fetch(digest, &mut contents);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(contents.len(), MARY_DATA.len());
        assert_eq!(contents[..8], MARY_DATA[..8]);

        // fetch (uppercase)
        let mut contents: Vec<u8> = Vec::new();
        let upper = digest.to_uppercase();
        let result = blob_store.fetch(&upper, &mut contents);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(contents.len(), MARY_DATA.len());
        assert_eq!(contents[..8], MARY_DATA[..8]);

        // delete
        let result = blob_store.delete(digest);
        assert!(result.is_ok());
        assert!(!dest_path.exists());

        // tear down
        std::fs::remove_dir_all(basepath).unwrap();
    }
}
