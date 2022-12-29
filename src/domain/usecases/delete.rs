//
// Copyright (c) 2022 Nathan Fiedler
//
use crate::domain::entities::Checksum;
use crate::domain::repositories::BlobRepository;
use anyhow::Error;
use std::cmp;
use std::fmt;
use std::sync::Arc;

pub struct DeleteBlob {
    blobs: Arc<dyn BlobRepository>,
}

impl DeleteBlob {
    pub fn new(blobs: Arc<dyn BlobRepository>) -> Self {
        Self { blobs }
    }
}

impl<'b> super::UseCase<(), Params> for DeleteBlob {
    fn call(&self, params: Params) -> Result<(), Error> {
        self.blobs.delete(&params.digest)
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

    #[test]
    fn test_delete_error() {
        // arrange
        let mut blobs = MockBlobRepository::new();
        blobs.expect_delete().returning(|_| Err(anyhow!("oh no")));
        // act
        let digest = Checksum::SHA1("9873bd2820da36edcc4f52e23b6b2e047257a4cd".into());
        let usecase = DeleteBlob::new(Arc::new(blobs));
        let params = Params::new(digest);
        let result = usecase.call(params);
        // assert
        assert!(result.is_err());
        let err_string = result.unwrap_err().to_string();
        assert!(err_string.contains("oh no"));
    }

    #[test]
    fn test_delete_ok() {
        // arrange
        let mut blobs = MockBlobRepository::new();
        blobs.expect_delete().return_once(move |_| Ok(()));
        // act
        let digest = Checksum::SHA1("9873bd2820da36edcc4f52e23b6b2e047257a4cd".into());
        let usecase = DeleteBlob::new(Arc::new(blobs));
        let params = Params::new(digest);
        let result = usecase.call(params);
        // assert
        assert!(result.is_ok());
    }
}
