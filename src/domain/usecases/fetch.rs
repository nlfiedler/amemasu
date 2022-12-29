//
// Copyright (c) 2022 Nathan Fiedler
//
use crate::domain::entities::{Blob, Checksum};
use crate::domain::repositories::BlobRepository;
use crate::domain::usecases::verify_digest;
use anyhow::{anyhow, Error};
use std::cmp;
use std::fmt;
use std::sync::Arc;

pub struct FetchBlob {
    blobs: Arc<dyn BlobRepository>,
}

impl FetchBlob {
    pub fn new(blobs: Arc<dyn BlobRepository>) -> Self {
        Self { blobs }
    }
}

impl<'a, 'b> super::UseCase<Option<Blob<'b>>, Params> for FetchBlob {
    fn call(&self, params: Params) -> Result<Option<Blob<'b>>, Error> {
        let maybe_blob = self.blobs.fetch(&params.digest)?;
        if let Some(ref blob) = maybe_blob {
            if !verify_digest(blob)? {
                return Err(anyhow!("digest mismatch"));
            }
        }
        Ok(maybe_blob)
    }
}

#[derive(Clone)]
pub struct Params {
    digest: Checksum,
}

impl Params {
    pub fn new(digest: Checksum) -> Self {
        Self { digest }
    }
}

impl fmt::Display for Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Params({:?})", self.digest)
    }
}

impl cmp::PartialEq for Params {
    fn eq(&self, other: &Self) -> bool {
        self.digest == other.digest
    }
}

impl cmp::Eq for Params {}

#[cfg(test)]
mod tests {
    use super::super::UseCase;
    use super::*;
    use crate::domain::repositories::MockBlobRepository;
    use anyhow::anyhow;
    use once_cell::sync::Lazy;

    static MARY_DATA: Lazy<Vec<u8>> = Lazy::new(|| {
        vec![
            0x6d, 0x61, 0x72, 0x79, 0x20, 0x68, 0x61, 0x64, 0x20, 0x61, 0x20, 0x6c, 0x69, 0x74,
            0x74, 0x6c, 0x65, 0x20, 0x6c, 0x61, 0x6d, 0x62, 0x0a,
        ]
    });

    #[test]
    fn test_fetch_error() {
        // arrange
        let mut blobs = MockBlobRepository::new();
        blobs.expect_fetch().returning(|_| Err(anyhow!("oh no")));
        // act
        let usecase = FetchBlob::new(Arc::new(blobs));
        let digest = Checksum::SHA1("cafebabe".into());
        let params = Params::new(digest);
        let result = usecase.call(params);
        // assert
        assert!(result.is_err());
        let err_string = result.unwrap_err().to_string();
        assert!(err_string.contains("oh no"));
    }

    #[test]
    fn test_fetch_not_found() {
        // arrange
        let mut blobs = MockBlobRepository::new();
        blobs.expect_fetch().returning(|_| Ok(None));
        // act
        let usecase = FetchBlob::new(Arc::new(blobs));
        let digest = Checksum::SHA1("cafebabe".into());
        let params = Params::new(digest);
        let result = usecase.call(params);
        // assert
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_fetch_digest() {
        // arrange
        let digest = Checksum::SHA1("cafebabe".into());
        let param_digest = digest.clone();
        let blobby = Blob::new::<&[u8]>(digest, &MARY_DATA);
        let mut blobs = MockBlobRepository::new();
        blobs.expect_fetch().return_once(move |_| Ok(Some(blobby)));
        // act
        let usecase = FetchBlob::new(Arc::new(blobs));
        let params = Params::new(param_digest);
        let result = usecase.call(params);
        // assert
        assert!(result.is_err());
        let err_string = result.unwrap_err().to_string();
        assert!(err_string.contains("digest mismatch"));
    }

    #[test]
    fn test_fetch_ok() {
        // arrange
        let digest = Checksum::SHA1("9873bd2820da36edcc4f52e23b6b2e047257a4cd".into());
        let param_digest = digest.clone();
        let blobby = Blob::new::<&[u8]>(digest, &MARY_DATA);
        let mut blobs = MockBlobRepository::new();
        blobs.expect_fetch().return_once(move |_| Ok(Some(blobby)));
        // act
        let usecase = FetchBlob::new(Arc::new(blobs));
        let params = Params::new(param_digest);
        let result = usecase.call(params);
        // assert
        assert!(result.is_ok());
    }
}
