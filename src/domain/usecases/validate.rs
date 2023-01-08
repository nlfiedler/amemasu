//
// Copyright (c) 2023 Nathan Fiedler
//
use crate::domain::repositories::KeyRepository;
use anyhow::{anyhow, Error};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde_json::Value;
use std::cmp;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

///
/// Validate a given access token against the configured JWKS (issuer) and
/// return the value for the `purpose` claim from the payload.
///
pub struct ValidateToken {
    keys: Arc<dyn KeyRepository>,
}

impl ValidateToken {
    pub fn new(keys: Arc<dyn KeyRepository>) -> Self {
        Self { keys }
    }
}

impl super::UseCase<Option<String>, Params> for ValidateToken {
    fn call(&self, params: Params) -> Result<Option<String>, Error> {
        if let Some(jwk) = self.keys.find_key(params.key_id.as_ref().map(|x| &**x))? {
            let decoder = DecodingKey::from_jwk(&jwk)?;
            let mut validation = Validation::new(Algorithm::RS256);
            if let Some(aud) = params.audience {
                // Merely setting the audience does not require that it be
                // present in the claims, only that if it were present that the
                // value matches expectations.
                validation.set_required_spec_claims(&["exp", "aud"]);
                validation.set_audience(&[aud]);
            }
            let token_data =
                decode::<HashMap<String, Value>>(&params.token, &decoder, &validation)?;
            // extract `purpose` claim and return its value
            if let Some(purpose) = token_data.claims.get("purpose") {
                if let Some(as_str) = purpose.as_str() {
                    return Ok(Some(as_str.to_owned()));
                }
            }
            return Ok(None);
        }
        Err(anyhow!("token could not be validated"))
    }
}

#[derive(Clone)]
pub struct Params {
    token: String,
    key_id: Option<String>,
    audience: Option<String>,
}

impl Params {
    pub fn new(token: String, key_id: Option<String>, audience: Option<String>) -> Self {
        Self {
            token,
            key_id,
            audience,
        }
    }
}

impl fmt::Display for Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Params({:?}/{:?})", self.key_id, self.audience)
    }
}

impl cmp::PartialEq for Params {
    fn eq(&self, other: &Self) -> bool {
        self.token == other.token
    }
}

impl cmp::Eq for Params {}

#[cfg(test)]
mod test {
    use super::*;
    use crate::data::repositories::KeyRepositoryImpl;
    use crate::data::sources::KeySetDataSourceImpl;
    use crate::domain::repositories::MockKeyRepository;
    use crate::domain::usecases::UseCase;
    use actix_web::web::Buf;
    use hyper::{Body, Client, Method, Request};
    use hyper_tls::HttpsConnector;
    use jsonwebtoken::jwk::JwkSet;
    use serde_json::Value;

    #[test]
    fn test_validate_bad_base64() {
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
        let mut mock = MockKeyRepository::new();
        mock.expect_find_key().returning(move |_| {
            let jwks: JwkSet = serde_json::from_str(&raw_data)?;
            Ok(Some(jwks.keys[0].clone()))
        });
        // act
        let usecase = ValidateToken::new(Arc::new(mock));
        let params = Params {
            token: "not.valid.token".into(),
            key_id: None,
            audience: None,
        };
        let result = usecase.call(params);
        // assert
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Base64 error"));
    }

    #[test]
    fn test_validate_invalid_sig() {
        // arrange
        let access_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImI3NTQ5YWYyLTVkZjgtNGMwNS1hYWQ1LWQ5YzVjZWU3MDk3YiJ9.eyJzdWIiOiJqb2huZG9lIiwiZXhwIjoxNjcyODk5MTQ5LCJpYXQiOjE2NzI4OTU1NDksImlzcyI6Imh0dHA6Ly8xOTIuMTY4LjEuMzozMDAwIiwicHVycG9zZSI6InJlYWQiLCJuYW1lIjoiSm9obiBEb2UifQ.YpNPHR5GYf6lRdCju0H8yd7BVnO9S7R5s4HTOAjKqKqGDlb7bCXjdMpbCdF6fv66Ss9dHaVrvU_StfoqbvYWwmpi5PrS6hM_KU6h_1Dk6ECW3xFol5G7kzjjjzG2WvBA8cPG7DbVw7T8_50gcrdytoLeLKLnfo93f_NaPScHjog67T5f9mbmjxTzEqHZ_BAVxpNPYpJxSrajHLdKpGT3FvH_s-yHK4u0tsZmybtnjqwiHlNd_xdtUi-AM_VF3Sdu9hGsazjXUy5yq0mFDkXCSDphXJTzEiXINw93LAmDrm9atdjDExMLyf79Mk-4Jt8SJuI7_nOPqg7I06_yInW6bA";
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
        let mut mock = MockKeyRepository::new();
        mock.expect_find_key().returning(move |_| {
            let jwks: JwkSet = serde_json::from_str(&raw_data)?;
            Ok(Some(jwks.keys[0].clone()))
        });
        // act
        let usecase = ValidateToken::new(Arc::new(mock));
        let params = Params {
            token: access_token.to_owned(),
            key_id: None,
            audience: None,
        };
        let result = usecase.call(params);
        // assert
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("InvalidSignature"));
    }

    #[test]
    fn test_validate_expired() {
        // arrange
        let access_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImI3NTQ5YWYyLTVkZjgtNGMwNS1hYWQ1LWQ5YzVjZWU3MDk3YiJ9.eyJzdWIiOiJqb2huZG9lIiwiZXhwIjoxNjcyODk5MTQ5LCJpYXQiOjE2NzI4OTU1NDksImlzcyI6Imh0dHA6Ly8xOTIuMTY4LjEuMzozMDAwIiwicHVycG9zZSI6InJlYWQiLCJuYW1lIjoiSm9obiBEb2UifQ.YpNPHR5GYf6lRdCju0H8yd7BVnO9S7R5s4HTOAjKqKqGDlb7bCXjdMpbCdF6fv66Ss9dHaVrvU_StfoqbvYWwmpi5PrS6hM_KU6h_1Dk6ECW3xFol5G7kzjjjzG2WvBA8cPG7DbVw7T8_50gcrdytoLeLKLnfo93f_NaPScHjog67T5f9mbmjxTzEqHZ_BAVxpNPYpJxSrajHLdKpGT3FvH_s-yHK4u0tsZmybtnjqwiHlNd_xdtUi-AM_VF3Sdu9hGsazjXUy5yq0mFDkXCSDphXJTzEiXINw93LAmDrm9atdjDExMLyf79Mk-4Jt8SJuI7_nOPqg7I06_yInW6bA";
        let raw_data = r#"{
"keys":[
    {
    "alg":"RS256","kty":"RSA","use":"sig",
    "n":"uwRXRCjow4hPZyguA6V4SK2jzcggA6tDlbYvx1m0a8X4Qu1aQ7UWxTXQRFkKgEY4LQkCEs5MJy8JMAX56p4CU6rHB7Elth_JtPToYEPGjmAFzH_2D7LQ49xk4jNJhAs_g4wmcHEPnesiijEc0wc9ZnI6-W2YT2PNAm3r4LYUQu6KS2eRGkHA_6Hi4gRWjFHPk2_j0LYTg3eQOu33Lgum1REusY1omMgflSF1eZdY_-y8HUy4sVNmJ61SOLAqBaICsv0eXtYM5rwR9Ioc0IXIxwQ_hhPMDn4Ck9AN8OqPIX4Cep3ocd3NSao66cwtsZI6qJz6Y338IjM98hhzAsnOSQ",
    "e":"AQAB","kid":"b7549af2-5df8-4c05-aad5-d9c5cee7097b"
    }
]}"#;
        let mut mock = MockKeyRepository::new();
        mock.expect_find_key().returning(move |_| {
            let jwks: JwkSet = serde_json::from_str(&raw_data)?;
            Ok(Some(jwks.keys[0].clone()))
        });
        // act
        let usecase = ValidateToken::new(Arc::new(mock));
        let params = Params {
            token: access_token.into(),
            key_id: Some("b7549af2-5df8-4c05-aad5-d9c5cee7097b".into()),
            audience: None,
        };
        let result = usecase.call(params);
        // assert
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ExpiredSignature"));
    }

    async fn fetch_access_token(base_uri: &str) -> Result<String, Error> {
        let https = HttpsConnector::new();
        let client = Client::builder().build::<_, hyper::Body>(https);

        // retrieve an access token
        let tokens_uri = format!("{}/tokens", base_uri);
        let req = Request::builder()
            .method(Method::POST)
            .uri(&tokens_uri)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(
                r#"grant_type=password&username=johndoe&password=tiger2"#,
            ))?;
        let resp = client.request(req).await?;
        if resp.status() != 200 {
            let msg = "tokens request failed";
            return Err(anyhow!(msg));
        }
        let body = hyper::body::to_bytes(resp.into_body()).await?;
        let buf = body.reader();
        let raw_value: Value = serde_json::from_reader(buf)?;
        let token = raw_value.as_object().unwrap();
        let access_token = token["access_token"].as_str().unwrap();
        Ok(access_token.to_owned())
    }

    #[tokio::test]
    async fn test_validate_live_test() {
        // set up the environment and remote connection
        dotenv::dotenv().ok();
        let uri_var = std::env::var("ISSUER_URI");
        if let Ok(issuer_uri) = uri_var {
            // fetch an access token from the test issuer
            let access_token = fetch_access_token(&issuer_uri).await.unwrap();
            // validate the token against the same issuer
            let data_source = KeySetDataSourceImpl::new(issuer_uri.clone());
            let repo = KeyRepositoryImpl::new(Arc::new(data_source));
            let usecase = ValidateToken::new(Arc::new(repo));
            let params = Params {
                token: access_token.into(),
                key_id: None,
                audience: None,
            };
            let result = usecase.call(params);
            // assert
            assert!(result.is_ok());
            let option = result.unwrap();
            assert!(option.is_some());
            let purpose = option.unwrap();
            assert_eq!(purpose, "read");
        }
    }

    #[tokio::test]
    async fn test_validate_missing_aud() {
        // set up the environment and remote connection
        dotenv::dotenv().ok();
        let uri_var = std::env::var("ISSUER_URI");
        if let Ok(issuer_uri) = uri_var {
            // fetch an access token from the test issuer
            let access_token = fetch_access_token(&issuer_uri).await.unwrap();
            // validate the token against the same issuer
            let data_source = KeySetDataSourceImpl::new(issuer_uri.clone());
            let repo = KeyRepositoryImpl::new(Arc::new(data_source));
            let usecase = ValidateToken::new(Arc::new(repo));
            let params = Params {
                token: access_token.into(),
                key_id: None,
                audience: Some("foobar".into()),
            };
            let result = usecase.call(params);
            // assert
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Missing required claim: aud"));
        }
    }
}
