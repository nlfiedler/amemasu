//
// Copyright (c) 2022 Nathan Fiedler
//
use crate::domain::entities::{Blob, Checksum};
use anyhow::{anyhow, Error};
use std::cmp;
use std::fmt;

pub mod delete;
pub mod fetch;
pub mod store;

/// `UseCase` is the interface by which all use cases are invoked.
pub trait UseCase<Type, Params> {
    fn call(&self, params: Params) -> Result<Type, Error>;
}

/// `NoParams` is the type for use cases that do not take arguments.
pub struct NoParams {}

impl fmt::Display for NoParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NoParams()")
    }
}

impl cmp::PartialEq for NoParams {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl cmp::Eq for NoParams {}

// Verify the blob data matches the digest. Returns true if the digest matches
// the content based on the supposed algorithm, false otherwise.
fn verify_digest(blob: &Blob) -> Result<bool, Error> {
    let actual = if blob.digest.is_sha1() {
        Checksum::sha1_from_bytes(&blob.data)
    } else if blob.digest.is_sha224() {
        Checksum::sha224_from_bytes(&blob.data)
    } else if blob.digest.is_sha256() {
        Checksum::sha256_from_bytes(&blob.data)
    } else {
        return Err(anyhow!("unsupported algorithm"));
    };
    Ok(actual == blob.digest)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_verify_digest() {
        let data = vec![
            0x6d, 0x61, 0x72, 0x79, 0x20, 0x68, 0x61, 0x64, 0x20, 0x61, 0x20, 0x6c, 0x69, 0x74,
            0x74, 0x6c, 0x65, 0x20, 0x6c, 0x61, 0x6d, 0x62, 0x0a,
        ];
        // digest does not match content
        let digest = Checksum::SHA1("cafebabe".into());
        let blob = Blob::new(digest, &data);
        let result = verify_digest(&blob);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false);

        // sha1 digest matches content
        let digest = Checksum::SHA1("9873bd2820da36edcc4f52e23b6b2e047257a4cd".into());
        let blob = Blob::new(digest, &data);
        let result = verify_digest(&blob);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);

        // sha224 digest matches content
        let digest =
            Checksum::SHA224("004f1b28ecae2f4d1828f4c07e69bb4454593f44ed39f890bc46bc63".into());
        let blob = Blob::new(digest, &data);
        let result = verify_digest(&blob);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);

        // sha256 digest matches content
        let digest = Checksum::SHA256(
            "e8d947bb5445001e54ae5589847f060f8cd4fe8ee3be4a69652f3ca9aade560b".into(),
        );
        let blob = Blob::new(digest, &data);
        let result = verify_digest(&blob);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
    }
}
