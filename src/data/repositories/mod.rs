//
// Copyright (c) 2022 Nathan Fiedler
//
use crate::data::sources::KeySetDataSource;
use crate::domain::entities::{Blob, Checksum};
use crate::domain::repositories::{BlobRepository, KeyRepository};
use anyhow::{anyhow, Error};
use jsonwebtoken::jwk::{Jwk, JwkSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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

pub struct KeyRepositoryImpl {
    keysource: Arc<dyn KeySetDataSource>,
}

impl KeyRepositoryImpl {
    pub fn new(keysource: Arc<dyn KeySetDataSource>) -> Self {
        Self { keysource }
    }
}

impl KeyRepository for KeyRepositoryImpl {
    fn find_key(&self, key_id: Option<&str>) -> Result<Option<Jwk>, Error> {
        let raw_data = self.keysource.get_key_set()?;
        let jwks: JwkSet = serde_json::from_str(&raw_data)?;
        if let Some(kid) = key_id {
            return Ok(jwks.find(kid).cloned());
        }
        if !jwks.keys.is_empty() {
            return Ok(Some(jwks.keys[0].to_owned()));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::data::sources::MockKeySetDataSource;
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

    #[test]
    fn test_key_fetch_err() {
        // arrange
        let mut mock = MockKeySetDataSource::new();
        mock.expect_get_key_set()
            .returning(move || Err(anyhow!("oh no")));
        // act
        let repo = KeyRepositoryImpl::new(Arc::new(mock));
        let result = repo.find_key(None);
        // assert
        assert!(result.is_err());
    }

    #[test]
    fn test_key_fetch_missing() {
        // arrange
        let raw_data = r#"{
"keys": [
    {
    "alg": "RS256",
    "kty": "RSA",
    "use": "sig",
    "x5c": [
        "MIIC+DCCAeCgAwIBAgIJBIGjYW6hFpn2MA0GCSqGSIb3DQEBBQUAMCMxITAfBgNVBAMTGGN1c3RvbWVyLWRlbW9zLmF1dGgwLmNvbTAeFw0xNjExMjIyMjIyMDVaFw0zMDA4MDEyMjIyMDVaMCMxITAfBgNVBAMTGGN1c3RvbWVyLWRlbW9zLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMnjZc5bm/eGIHq09N9HKHahM7Y31P0ul+A2wwP4lSpIwFrWHzxw88/7Dwk9QMc+orGXX95R6av4GF+Es/nG3uK45ooMVMa/hYCh0Mtx3gnSuoTavQEkLzCvSwTqVwzZ+5noukWVqJuMKNwjL77GNcPLY7Xy2/skMCT5bR8UoWaufooQvYq6SyPcRAU4BtdquZRiBT4U5f+4pwNTxSvey7ki50yc1tG49Per/0zA4O6Tlpv8x7Red6m1bCNHt7+Z5nSl3RX/QYyAEUX1a28VcYmR41Osy+o2OUCXYdUAphDaHo4/8rbKTJhlu8jEcc1KoMXAKjgaVZtG/v5ltx6AXY0CAwEAAaMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQUQxFG602h1cG+pnyvJoy9pGJJoCswDQYJKoZIhvcNAQEFBQADggEBAGvtCbzGNBUJPLICth3mLsX0Z4z8T8iu4tyoiuAshP/Ry/ZBnFnXmhD8vwgMZ2lTgUWwlrvlgN+fAtYKnwFO2G3BOCFw96Nm8So9sjTda9CCZ3dhoH57F/hVMBB0K6xhklAc0b5ZxUpCIN92v/w+xZoz1XQBHe8ZbRHaP1HpRM4M7DJk2G5cgUCyu3UBvYS41sHvzrxQ3z7vIePRA4WF4bEkfX12gvny0RsPkrbVMXX1Rj9t6V7QXrbPYBAO+43JvDGYawxYVvLhz+BJ45x50GFQmHszfY3BR9TPK8xmMmQwtIvLu1PMttNCs7niCYkSiUv2sc2mlq1i3IashGkkgmo="
    ],
    "n": "yeNlzlub94YgerT030codqEztjfU_S6X4DbDA_iVKkjAWtYfPHDzz_sPCT1Axz6isZdf3lHpq_gYX4Sz-cbe4rjmigxUxr-FgKHQy3HeCdK6hNq9ASQvMK9LBOpXDNn7mei6RZWom4wo3CMvvsY1w8tjtfLb-yQwJPltHxShZq5-ihC9irpLI9xEBTgG12q5lGIFPhTl_7inA1PFK97LuSLnTJzW0bj096v_TMDg7pOWm_zHtF53qbVsI0e3v5nmdKXdFf9BjIARRfVrbxVxiZHjU6zL6jY5QJdh1QCmENoejj_ytspMmGW7yMRxzUqgxcAqOBpVm0b-_mW3HoBdjQ",
    "e": "AQAB",
    "kid": "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg",
    "x5t": "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg"
    }
]}"#;
        let mut mock = MockKeySetDataSource::new();
        mock.expect_get_key_set()
            .returning(move || Ok(raw_data.into()));
        // act
        let repo = KeyRepositoryImpl::new(Arc::new(mock));
        let result = repo.find_key(Some("notfound".into()));
        // assert
        assert!(result.is_ok());
        let option = result.unwrap();
        assert!(option.is_none());
    }

    #[test]
    fn test_key_fetch_first() {
        // arrange
        let raw_data = r#"{
"keys": [
    {
    "alg": "RS256",
    "kty": "RSA",
    "use": "sig",
    "x5c": [
        "MIIC+DCCAeCgAwIBAgIJBIGjYW6hFpn2MA0GCSqGSIb3DQEBBQUAMCMxITAfBgNVBAMTGGN1c3RvbWVyLWRlbW9zLmF1dGgwLmNvbTAeFw0xNjExMjIyMjIyMDVaFw0zMDA4MDEyMjIyMDVaMCMxITAfBgNVBAMTGGN1c3RvbWVyLWRlbW9zLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMnjZc5bm/eGIHq09N9HKHahM7Y31P0ul+A2wwP4lSpIwFrWHzxw88/7Dwk9QMc+orGXX95R6av4GF+Es/nG3uK45ooMVMa/hYCh0Mtx3gnSuoTavQEkLzCvSwTqVwzZ+5noukWVqJuMKNwjL77GNcPLY7Xy2/skMCT5bR8UoWaufooQvYq6SyPcRAU4BtdquZRiBT4U5f+4pwNTxSvey7ki50yc1tG49Per/0zA4O6Tlpv8x7Red6m1bCNHt7+Z5nSl3RX/QYyAEUX1a28VcYmR41Osy+o2OUCXYdUAphDaHo4/8rbKTJhlu8jEcc1KoMXAKjgaVZtG/v5ltx6AXY0CAwEAAaMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQUQxFG602h1cG+pnyvJoy9pGJJoCswDQYJKoZIhvcNAQEFBQADggEBAGvtCbzGNBUJPLICth3mLsX0Z4z8T8iu4tyoiuAshP/Ry/ZBnFnXmhD8vwgMZ2lTgUWwlrvlgN+fAtYKnwFO2G3BOCFw96Nm8So9sjTda9CCZ3dhoH57F/hVMBB0K6xhklAc0b5ZxUpCIN92v/w+xZoz1XQBHe8ZbRHaP1HpRM4M7DJk2G5cgUCyu3UBvYS41sHvzrxQ3z7vIePRA4WF4bEkfX12gvny0RsPkrbVMXX1Rj9t6V7QXrbPYBAO+43JvDGYawxYVvLhz+BJ45x50GFQmHszfY3BR9TPK8xmMmQwtIvLu1PMttNCs7niCYkSiUv2sc2mlq1i3IashGkkgmo="
    ],
    "n": "yeNlzlub94YgerT030codqEztjfU_S6X4DbDA_iVKkjAWtYfPHDzz_sPCT1Axz6isZdf3lHpq_gYX4Sz-cbe4rjmigxUxr-FgKHQy3HeCdK6hNq9ASQvMK9LBOpXDNn7mei6RZWom4wo3CMvvsY1w8tjtfLb-yQwJPltHxShZq5-ihC9irpLI9xEBTgG12q5lGIFPhTl_7inA1PFK97LuSLnTJzW0bj096v_TMDg7pOWm_zHtF53qbVsI0e3v5nmdKXdFf9BjIARRfVrbxVxiZHjU6zL6jY5QJdh1QCmENoejj_ytspMmGW7yMRxzUqgxcAqOBpVm0b-_mW3HoBdjQ",
    "e": "AQAB",
    "kid": "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg",
    "x5t": "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg"
    }
]}"#;
        let mut mock = MockKeySetDataSource::new();
        mock.expect_get_key_set()
            .returning(move || Ok(raw_data.into()));
        // act
        let repo = KeyRepositoryImpl::new(Arc::new(mock));
        let result = repo.find_key(None);
        // assert
        assert!(result.is_ok());
        let option = result.unwrap();
        assert!(option.is_some());
        let jwk = option.unwrap();
        assert_eq!(jwk.common.key_algorithm, Some(jsonwebtoken::jwk::KeyAlgorithm::RS256));
    }

    #[test]
    fn test_key_fetch_match() {
        // arrange
        let raw_data = r#"{
"keys": [
    {
    "alg": "RS256",
    "kty": "RSA",
    "use": "sig",
    "x5c": [
        "MIIC+DCCAeCgAwIBAgIJBIGjYW6hFpn2MA0GCSqGSIb3DQEBBQUAMCMxITAfBgNVBAMTGGN1c3RvbWVyLWRlbW9zLmF1dGgwLmNvbTAeFw0xNjExMjIyMjIyMDVaFw0zMDA4MDEyMjIyMDVaMCMxITAfBgNVBAMTGGN1c3RvbWVyLWRlbW9zLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMnjZc5bm/eGIHq09N9HKHahM7Y31P0ul+A2wwP4lSpIwFrWHzxw88/7Dwk9QMc+orGXX95R6av4GF+Es/nG3uK45ooMVMa/hYCh0Mtx3gnSuoTavQEkLzCvSwTqVwzZ+5noukWVqJuMKNwjL77GNcPLY7Xy2/skMCT5bR8UoWaufooQvYq6SyPcRAU4BtdquZRiBT4U5f+4pwNTxSvey7ki50yc1tG49Per/0zA4O6Tlpv8x7Red6m1bCNHt7+Z5nSl3RX/QYyAEUX1a28VcYmR41Osy+o2OUCXYdUAphDaHo4/8rbKTJhlu8jEcc1KoMXAKjgaVZtG/v5ltx6AXY0CAwEAAaMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQUQxFG602h1cG+pnyvJoy9pGJJoCswDQYJKoZIhvcNAQEFBQADggEBAGvtCbzGNBUJPLICth3mLsX0Z4z8T8iu4tyoiuAshP/Ry/ZBnFnXmhD8vwgMZ2lTgUWwlrvlgN+fAtYKnwFO2G3BOCFw96Nm8So9sjTda9CCZ3dhoH57F/hVMBB0K6xhklAc0b5ZxUpCIN92v/w+xZoz1XQBHe8ZbRHaP1HpRM4M7DJk2G5cgUCyu3UBvYS41sHvzrxQ3z7vIePRA4WF4bEkfX12gvny0RsPkrbVMXX1Rj9t6V7QXrbPYBAO+43JvDGYawxYVvLhz+BJ45x50GFQmHszfY3BR9TPK8xmMmQwtIvLu1PMttNCs7niCYkSiUv2sc2mlq1i3IashGkkgmo="
    ],
    "n": "yeNlzlub94YgerT030codqEztjfU_S6X4DbDA_iVKkjAWtYfPHDzz_sPCT1Axz6isZdf3lHpq_gYX4Sz-cbe4rjmigxUxr-FgKHQy3HeCdK6hNq9ASQvMK9LBOpXDNn7mei6RZWom4wo3CMvvsY1w8tjtfLb-yQwJPltHxShZq5-ihC9irpLI9xEBTgG12q5lGIFPhTl_7inA1PFK97LuSLnTJzW0bj096v_TMDg7pOWm_zHtF53qbVsI0e3v5nmdKXdFf9BjIARRfVrbxVxiZHjU6zL6jY5QJdh1QCmENoejj_ytspMmGW7yMRxzUqgxcAqOBpVm0b-_mW3HoBdjQ",
    "e": "AQAB",
    "kid": "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg",
    "x5t": "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg"
    }
]}"#;
        let mut mock = MockKeySetDataSource::new();
        mock.expect_get_key_set()
            .returning(move || Ok(raw_data.into()));
        // act
        let repo = KeyRepositoryImpl::new(Arc::new(mock));
        let result = repo.find_key(Some("NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg"));
        // assert
        assert!(result.is_ok());
        let option = result.unwrap();
        assert!(option.is_some());
        let jwk = option.unwrap();
        assert_eq!(jwk.common.key_algorithm, Some(jsonwebtoken::jwk::KeyAlgorithm::RS256));
    }
}
