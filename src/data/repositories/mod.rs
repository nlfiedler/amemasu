//
// Copyright (c) 2022 Nathan Fiedler
//
use crate::domain::entities::{Blob, Checksum};
use crate::domain::repositories::BlobRepository;
use anyhow::{anyhow, Error};
use std::fs;
use std::path::{Path, PathBuf};

pub struct BlobRepositoryImpl {
    basepath: PathBuf,
    short_prefix: bool,
}

impl BlobRepositoryImpl {
    pub fn new(basepath: &Path) -> Self {
        Self {
            basepath: basepath.to_path_buf(),
            short_prefix: true,
        }
    }

    fn blob_path(&self, digest: &Checksum) -> Result<PathBuf, Error> {
        let hash_value = digest.digest();
        let rel_path = if self.short_prefix {
            PathBuf::from(&hash_value[0..2]).join(&hash_value[2..])
        } else {
            PathBuf::from(&hash_value[0..3]).join(&hash_value[3..])
        };
        let mut full_path = self.basepath.clone();
        full_path.push(rel_path);
        Ok(full_path)
    }
}

impl BlobRepository for BlobRepositoryImpl {
    fn store<'a>(&self, blob: &'a Blob<'a>) -> Result<(), Error> {
        let blob_path = self.blob_path(&blob.digest)?;
        let parent_path = blob_path
            .parent()
            .ok_or_else(|| anyhow!(format!("no parent for {:?}", blob_path)))?;
        std::fs::create_dir_all(parent_path)?;
        fs::write(&blob_path, &blob.data)?;
        Ok(())
    }

    fn fetch<'a>(&self, digest: &Checksum) -> Result<Option<Blob<'a>>, Error> {
        let blob_path = self.blob_path(digest)?;
        if blob_path.try_exists()? {
            let contents = fs::read(blob_path)?;
            let blob = Blob::new(digest.clone(), contents);
            Ok(Some(blob))
        } else {
            Ok(None)
        }
    }

    fn delete(&self, digest: &Checksum) -> Result<(), Error> {
        let blob_path = self.blob_path(digest)?;
        if blob_path.try_exists()? {
            fs::remove_file(blob_path)?;
        }
        Ok(())
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
    fn test_store_ok() {
        // arrange
        let digest = Checksum::SHA1("9873bd2820da36edcc4f52e23b6b2e047257a4cd".into());
        let blobby = Blob::new::<&[u8]>(digest, &MARY_DATA);
        let tmpdir = tempdir().unwrap();
        let basepath = tmpdir.path().join("blobs");
        // act
        let repo = BlobRepositoryImpl::new(basepath.as_path());
        let result = repo.store(&blobby);
        // assert
        assert!(result.is_ok());
        let mut dest_path = basepath.clone();
        let id_path = "98/73bd2820da36edcc4f52e23b6b2e047257a4cd";
        dest_path.push(id_path);
        assert!(dest_path.exists());
        std::fs::remove_dir_all(basepath).unwrap();
    }

    #[test]
    fn test_fetch_none() {
        // arrange
        let digest = Checksum::SHA1("9873bd2820da36edcc4f52e23b6b2e047257a4cd".into());
        let tmpdir = tempdir().unwrap();
        let basepath = tmpdir.path().join("blobs");
        // act
        let repo = BlobRepositoryImpl::new(basepath.as_path());
        let result = repo.fetch(&digest);
        // assert
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_fetch_ok() {
        // arrange
        let digest = Checksum::SHA1("9873bd2820da36edcc4f52e23b6b2e047257a4cd".into());
        let blobby = Blob::new::<&[u8]>(digest, &MARY_DATA);
        let tmpdir = tempdir().unwrap();
        let basepath = tmpdir.path().join("blobs");
        let repo = BlobRepositoryImpl::new(basepath.as_path());
        let result = repo.store(&blobby);
        assert!(result.is_ok());
        // act
        let digest = Checksum::SHA1("9873bd2820da36edcc4f52e23b6b2e047257a4cd".into());
        let result = repo.fetch(&digest);
        // assert
        assert!(result.is_ok());
        let option = result.unwrap();
        assert!(option.is_some());
        let blobby = option.unwrap();
        assert!(blobby.digest == digest);
        assert_eq!(blobby.data.len(), MARY_DATA.len());
        assert_eq!(blobby.data[..8], MARY_DATA[..8]);
        std::fs::remove_dir_all(basepath).unwrap();
    }

    #[test]
    fn test_delete_none() {
        // arrange
        let digest = Checksum::SHA1("9873bd2820da36edcc4f52e23b6b2e047257a4cd".into());
        let tmpdir = tempdir().unwrap();
        let basepath = tmpdir.path().join("blobs");
        // act
        let repo = BlobRepositoryImpl::new(basepath.as_path());
        let result = repo.delete(&digest);
        // assert
        assert!(result.is_ok());
    }

    #[test]
    fn test_delete_ok() {
        // arrange
        let digest = Checksum::SHA1("9873bd2820da36edcc4f52e23b6b2e047257a4cd".into());
        let delete_digest = digest.clone();
        let blobby = Blob::new::<&[u8]>(digest, &MARY_DATA);
        let tmpdir = tempdir().unwrap();
        let basepath = tmpdir.path().join("blobs");
        let repo = BlobRepositoryImpl::new(basepath.as_path());
        let result = repo.store(&blobby);
        assert!(result.is_ok());
        let mut dest_path = basepath.clone();
        let id_path = "98/73bd2820da36edcc4f52e23b6b2e047257a4cd";
        dest_path.push(id_path);
        assert!(dest_path.exists());
        // act
        let result = repo.delete(&delete_digest);
        // assert
        assert!(result.is_ok());
        assert!(!dest_path.exists());
        std::fs::remove_dir_all(basepath).unwrap();
    }
}
