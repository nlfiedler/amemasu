//
// Copyright (c) 2022 Nathan Fiedler
//
use crate::domain::entities::{Blob, Checksum};
use anyhow::Error;
use jsonwebtoken::jwk::Jwk;
#[cfg(test)]
use mockall::{automock, predicate::*};

///
/// Repository for storing and retrieving blobs.
///
#[cfg_attr(test, automock)]
pub trait BlobRepository {
    /// Store the given blob data into the repository.
    fn store<'a>(&self, blob: &'a Blob<'a>) -> Result<(), Error>;

    /// Retrieve the blob identified by the given digest.
    fn fetch<'a>(&self, digest: &Checksum) -> Result<Option<Blob<'a>>, Error>;

    /// Remove the blob identified by the given digest.
    fn delete(&self, digest: &Checksum) -> Result<(), Error>;
}

///
/// Repository for retrieving and parsing JSON Web Key Sets.
///
#[cfg_attr(test, automock)]
pub trait KeyRepository {
    /// Retrieve the JWKS and attempt to find the give key.
    fn find_key<'a>(&self, key_id: Option<&'a str>) -> Result<Option<Jwk>, Error>;
}
