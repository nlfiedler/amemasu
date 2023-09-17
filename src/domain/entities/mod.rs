//
// Copyright (c) 2022 Nathan Fiedler
//
use anyhow::{anyhow, Error};
use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

///
/// `Checksum` represents a hash digest for a blob.
///
#[derive(Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub enum Checksum {
    SHA1(String),
    SHA224(String),
    SHA256(String),
}

impl Checksum {
    /// Compute the SHA1 hash digest of the given data.
    pub fn sha1_from_bytes(data: &[u8]) -> Checksum {
        use sha1::{Digest, Sha1};
        let mut hasher = Sha1::new();
        hasher.update(data);
        let digest = hasher.finalize();
        Checksum::SHA1(format!("{:x}", digest))
    }

    /// Compute the SHA224 hash digest of the given data.
    pub fn sha224_from_bytes(data: &[u8]) -> Checksum {
        use sha2::{Digest, Sha224};
        let mut hasher = Sha224::new();
        hasher.update(data);
        let digest = hasher.finalize();
        Checksum::SHA224(format!("{:x}", digest))
    }

    /// Compute the SHA256 hash digest of the given data.
    pub fn sha256_from_bytes(data: &[u8]) -> Checksum {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let digest = hasher.finalize();
        Checksum::SHA256(format!("{:x}", digest))
    }

    /// Return just the hash digest value without an algorithm prefix.
    pub fn digest(&self) -> String {
        match self {
            Checksum::SHA1(sum) => sum.to_owned(),
            Checksum::SHA224(sum) => sum.to_owned(),
            Checksum::SHA256(sum) => sum.to_owned(),
        }
    }

    /// Return `true` if this checksum is a SHA1.
    pub fn is_sha1(&self) -> bool {
        matches!(*self, Checksum::SHA1(_))
    }

    /// Return `true` if this checksum is a SHA224.
    pub fn is_sha224(&self) -> bool {
        matches!(*self, Checksum::SHA224(_))
    }

    /// Return `true` if this checksum is a SHA256.
    pub fn is_sha256(&self) -> bool {
        matches!(*self, Checksum::SHA256(_))
    }
}

impl Clone for Checksum {
    fn clone(&self) -> Self {
        match self {
            Checksum::SHA1(sum) => Checksum::SHA1(sum.to_owned()),
            Checksum::SHA224(sum) => Checksum::SHA224(sum.to_owned()),
            Checksum::SHA256(sum) => Checksum::SHA256(sum.to_owned()),
        }
    }
}

/// Useful for constructing a meaningless SHA1 value.
pub static FORTY_ZEROS: &str = "0000000000000000000000000000000000000000";

impl Default for Checksum {
    fn default() -> Self {
        Checksum::SHA1(String::from(FORTY_ZEROS))
    }
}

impl fmt::Display for Checksum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Checksum::SHA1(hash) => write!(f, "sha1-{}", hash),
            Checksum::SHA224(hash) => write!(f, "sha224-{}", hash),
            Checksum::SHA256(hash) => write!(f, "sha256-{}", hash),
        }
    }
}

impl FromStr for Checksum {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lower = s.to_owned().to_lowercase();
        if let Some(hash) = lower.strip_prefix("sha1-") {
            Ok(Checksum::SHA1(hash.to_owned()))
        } else if let Some(hash) = lower.strip_prefix("sha224-") {
            Ok(Checksum::SHA224(hash.to_owned()))
        } else if let Some(hash) = lower.strip_prefix("sha256-") {
            Ok(Checksum::SHA256(hash.to_owned()))
        } else {
            Err(anyhow!(format!("unsupported algorithm: {}", s)))
        }
    }
}

///
/// Blob represents a chunk of data identified by the associated hash digest.
///
#[derive(Clone, Debug)]
pub struct Blob<'a> {
    /// Hash digest of the blob data.
    pub digest: Checksum,
    /// Blob data as raw bytes.
    pub data: Cow<'a, [u8]>,
}

impl<'a> Blob<'a> {
    /// Construct a new Blob from the given data and corresponding digest.
    pub fn new<S>(digest: Checksum, data: S) -> Self
    where
        S: Into<Cow<'a, [u8]>>,
    {
        Blob {
            digest,
            data: data.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum_sort() {
        use std::cmp::Ordering;
        let c1a = Checksum::SHA1(String::from("65ace06cc7f835c497811ea7199968a119eeba4b"));
        let c1b = Checksum::SHA1(String::from("ee76ee57ba2fbc7690a38e125ec6af322288f750"));
        assert_eq!(Ordering::Less, c1a.partial_cmp(&c1b).unwrap());
        assert_eq!(Ordering::Greater, c1b.partial_cmp(&c1a).unwrap());
        let c2a = Checksum::SHA256(String::from(
            "a58dd8680234c1f8cc2ef2b325a43733605a7f16f288e072de8eae81fd8d6433",
        ));
        let c2b = Checksum::SHA256(String::from(
            "e03c4de56410b680ef69d8f8cfe140c54bb33f295015b40462d260deb9a60b82",
        ));
        assert_eq!(Ordering::Less, c2a.partial_cmp(&c2b).unwrap());
        assert_eq!(Ordering::Greater, c2b.partial_cmp(&c2a).unwrap());
        // all SHA1 values are always less than any SHA256 value
        assert_eq!(Ordering::Less, c1b.partial_cmp(&c2a).unwrap());
        assert_eq!(Ordering::Greater, c2a.partial_cmp(&c1b).unwrap());
    }

    #[test]
    fn test_checksum_fromstr() {
        // SHA1
        let result: Result<Checksum, Error> =
            FromStr::from_str("sha1-e7505beb754bed863e3885f73e3bb6866bdd7f8c");
        assert!(result.is_ok());
        let checksum = result.unwrap();
        assert_eq!(
            checksum,
            Checksum::SHA1(String::from("e7505beb754bed863e3885f73e3bb6866bdd7f8c"))
        );
        // SHA224
        let result: Result<Checksum, Error> =
            FromStr::from_str("sha224-e073079d080a12d1bcd88302834c3c11c53acacdf2e33faa6ed6c0b4");
        assert!(result.is_ok());
        let checksum = result.unwrap();
        assert_eq!(
            checksum,
            Checksum::SHA224(String::from(
                "e073079d080a12d1bcd88302834c3c11c53acacdf2e33faa6ed6c0b4"
            ))
        );
        // SHA256
        let result: Result<Checksum, Error> = FromStr::from_str(
            "sha256-a58dd8680234c1f8cc2ef2b325a43733605a7f16f288e072de8eae81fd8d6433",
        );
        assert!(result.is_ok());
        let checksum = result.unwrap();
        assert_eq!(
            checksum,
            Checksum::SHA256(String::from(
                "a58dd8680234c1f8cc2ef2b325a43733605a7f16f288e072de8eae81fd8d6433"
            ))
        );
        // invalid
        let result: Result<Checksum, Error> = FromStr::from_str("foobar");
        assert!(result.is_err());
    }

    #[test]
    fn test_checksum_data() {
        let data = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        let sha1 = Checksum::sha1_from_bytes(data);
        assert_eq!(
            sha1.to_string(),
            "sha1-e7505beb754bed863e3885f73e3bb6866bdd7f8c"
        );
        let sha224 = Checksum::sha224_from_bytes(data);
        assert_eq!(
            sha224.to_string(),
            "sha224-6b261393ad2025ac9165e16944d8655a8fbfe519ad16bac3afa524f2"
        );
        let sha256 = Checksum::sha256_from_bytes(data);
        assert_eq!(
            sha256.to_string(),
            "sha256-a58dd8680234c1f8cc2ef2b325a43733605a7f16f288e072de8eae81fd8d6433"
        );
    }
}
