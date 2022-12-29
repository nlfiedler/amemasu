//
// Copyright (c) 2022 Nathan Fiedler
//
use crate::domain::entities::Blob;
use crate::domain::repositories::BlobRepository;
use crate::domain::usecases::verify_digest;
use anyhow::{anyhow, Error};
use std::cmp;
use std::fmt;
use std::sync::Arc;

pub struct StoreBlob {
    blobs: Arc<dyn BlobRepository>,
}

impl StoreBlob {
    pub fn new(blobs: Arc<dyn BlobRepository>) -> Self {
        Self { blobs }
    }
}

impl<'a> super::UseCase<(), Params<'a>> for StoreBlob {
    fn call(&self, params: Params) -> Result<(), Error> {
        let matches = verify_digest(&params.blob)?;
        if matches {
            self.blobs.store(&params.blob)
        } else {
            Err(anyhow!("digest mismatch"))
        }
    }
}

#[derive(Clone)]
pub struct Params<'a> {
    blob: Blob<'a>,
}

impl<'a> Params<'a> {
    pub fn new(blob: Blob<'a>) -> Self {
        Self { blob }
    }
}

impl<'a> fmt::Display for Params<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Params({:?})", self.blob.digest)
    }
}

impl<'a> cmp::PartialEq for Params<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.blob.digest == other.blob.digest
    }
}

impl<'a> cmp::Eq for Params<'a> {}

#[cfg(test)]
mod tests {
    use super::super::UseCase;
    use super::*;
    use crate::domain::entities::Checksum;
    use crate::domain::repositories::MockBlobRepository;
    use once_cell::sync::Lazy;

    static MARY_DATA: Lazy<Vec<u8>> = Lazy::new(|| {
        vec![
            0x6d, 0x61, 0x72, 0x79, 0x20, 0x68, 0x61, 0x64, 0x20, 0x61, 0x20, 0x6c, 0x69, 0x74,
            0x74, 0x6c, 0x65, 0x20, 0x6c, 0x61, 0x6d, 0x62, 0x0a,
        ]
    });

    #[test]
    fn test_store_error() {
        // arrange
        let mut blobs = MockBlobRepository::new();
        blobs.expect_store().returning(|_| Err(anyhow!("oh no")));
        // act
        let usecase = StoreBlob::new(Arc::new(blobs));
        let digest = Checksum::SHA1("9873bd2820da36edcc4f52e23b6b2e047257a4cd".into());
        let blob = Blob::new::<&[u8]>(digest, &MARY_DATA);
        let params = Params::new(blob);
        let result = usecase.call(params);
        // assert
        assert!(result.is_err());
        let err_string = result.unwrap_err().to_string();
        assert!(err_string.contains("oh no"));
    }

    #[test]
    fn test_store_digest() {
        // arrange
        let mut blobs = MockBlobRepository::new();
        blobs.expect_store().returning(|_| Ok(()));
        // act
        let usecase = StoreBlob::new(Arc::new(blobs));
        let digest = Checksum::SHA1("cafebabe".into());
        let blob = Blob::new::<&[u8]>(digest, &MARY_DATA);
        let params = Params::new(blob);
        let result = usecase.call(params);
        // assert
        assert!(result.is_err());
        let err_string = result.unwrap_err().to_string();
        assert!(err_string.contains("digest mismatch"));
    }

    #[test]
    fn test_store_ok() {
        // arrange
        let mut blobs = MockBlobRepository::new();
        blobs.expect_store().returning(|_| Ok(()));
        // act
        let usecase = StoreBlob::new(Arc::new(blobs));
        let digest = Checksum::SHA1("9873bd2820da36edcc4f52e23b6b2e047257a4cd".into());
        let blob = Blob::new::<&[u8]>(digest, &MARY_DATA);
        let params = Params::new(blob);
        let result = usecase.call(params);
        // assert
        assert!(result.is_ok());
    }
}
