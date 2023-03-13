use argon2::Argon2;
use base64::{engine::general_purpose, Engine as _};
use bson::oid::ObjectId;
use jsonwebtoken::TokenData;
use mongodb::Collection;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::{
    error::Error,
    util::{hash_password, ObjectIdString},
};

use super::auth::{UserModel, UserRole};

#[derive(Clone)]
pub struct JwtState {
    validation: jsonwebtoken::Validation,
    header: jsonwebtoken::Header,

    encoding_key: jsonwebtoken::EncodingKey,
    decoding_key: jsonwebtoken::DecodingKey,
}

impl JwtState {
    pub fn new_from_env() -> Self {
        let secret_key = std::env::var("JWT_SECRET_KEY")
            .expect("Cannot retreive JWT_SECRET_KEY from environment variable.");
        let secret_key = general_purpose::STANDARD.decode(secret_key).unwrap();
        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(&secret_key).unwrap();

        let public_key = std::env::var("JWT_PUBLIC_KEY")
            .expect("Cannot retreive JWT_PUBLIC_KEY from environment variable.");
        let public_key = general_purpose::STANDARD.decode(public_key).unwrap();
        let decoding_key = jsonwebtoken::DecodingKey::from_rsa_pem(&public_key).unwrap();

        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.validate_exp = false;

        Self {
            header,
            validation,

            encoding_key,
            decoding_key,
        }
    }
}

#[derive(Clone)]
pub struct RefreshTokenCollection(pub Collection<RefreshTokenModel>);

pub fn current_timestamp() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RefreshTokenClaims {
    pub sub: ObjectIdString,
    pub user_id: ObjectIdString,
    pub exp: i64,
}

impl RefreshTokenClaims {
    pub fn is_expired(&self) -> bool {
        self.exp < current_timestamp().unix_timestamp()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RefreshTokenModel {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub user_id: ObjectId,
    pub token: String,
    pub expired_at: bson::DateTime,
}

pub async fn create_refresh_token(
    jwt_state: &JwtState,
    argon: &Argon2<'_>,
    RefreshTokenCollection(refresh_tokens): RefreshTokenCollection,
    user: &UserModel,
) -> Result<String, Error> {
    let (model, token) = generate_refresh_token_model(jwt_state, argon, user)?;

    refresh_tokens.insert_one(model, None).await?;

    Ok(token)
}

pub fn generate_refresh_token_model(
    jwt_state: &JwtState,
    argon: &Argon2,
    user: &UserModel,
) -> Result<(RefreshTokenModel, String), Error> {
    let expired_at = current_timestamp() + Duration::weeks(1);

    generate_refresh_token_model_with_exp(jwt_state, argon, user, expired_at)
}

pub fn generate_refresh_token_model_with_exp(
    jwt_state: &JwtState,
    argon: &Argon2,
    user: &UserModel,
    expired_at: OffsetDateTime,
) -> Result<(RefreshTokenModel, String), Error> {
    let id = ObjectId::new();
    let token = generate_refresh_token_string(
        jwt_state,
        id.clone(),
        user.id.clone(),
        expired_at.unix_timestamp(),
    )?;

    Ok((
        RefreshTokenModel {
            id,
            user_id: user.id,
            token: hash_password(argon, &token)?,
            expired_at: expired_at.into(),
        },
        token,
    ))
}

pub fn generate_refresh_token_string(
    jwt_state: &JwtState,
    id: ObjectId,
    user_id: ObjectId,
    exp: i64,
) -> Result<String, Error> {
    let claims = RefreshTokenClaims {
        sub: id.into(),
        user_id: user_id.into(),
        exp,
    };

    jsonwebtoken::encode(&jwt_state.header, &claims, &jwt_state.encoding_key).map_err(Into::into)
}

pub fn decode_refresh_token(
    jwt_state: &JwtState,
    token: &str,
) -> Result<TokenData<RefreshTokenClaims>, Error> {
    jsonwebtoken::decode(token, &jwt_state.decoding_key, &jwt_state.validation).map_err(Into::into)
}

#[derive(Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: ObjectIdString,
    pub user_role: UserRole,
    pub exp: i64,
}

impl AccessTokenClaims {
    pub fn is_expired(&self) -> bool {
        self.exp < current_timestamp().unix_timestamp()
    }
}

pub struct GenerateAccessTokenResponse {
    pub expired_at: OffsetDateTime,
    pub token: String,
}

pub fn generate_access_token(
    jwt_state: &JwtState,
    user: &UserModel,
) -> Result<GenerateAccessTokenResponse, Error> {
    let expired_at = current_timestamp() + Duration::minutes(10);
    let token = generate_access_token_with_exp(jwt_state, user, expired_at.unix_timestamp())?;

    Ok(GenerateAccessTokenResponse { expired_at, token })
}

pub fn generate_access_token_with_exp(
    jwt_state: &JwtState,
    user: &UserModel,
    exp: i64,
) -> Result<String, Error> {
    jsonwebtoken::encode(
        &jwt_state.header,
        &AccessTokenClaims {
            sub: user.id.into(),
            user_role: user.role,
            exp,
        },
        &jwt_state.encoding_key,
    )
    .map_err(Into::into)
}

pub fn decode_access_token(
    jwt_state: &JwtState,
    token: &str,
) -> Result<TokenData<AccessTokenClaims>, Error> {
    jsonwebtoken::decode(token, &jwt_state.decoding_key, &jwt_state.validation).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use bson::DateTime;

    use crate::util::verify_password;

    use super::*;

    #[test]
    pub fn test_refresh_token() {
        dotenvy::dotenv().unwrap();

        let jwt = JwtState::new_from_env();
        let argon = Argon2::default();

        let user_model = UserModel {
            id: ObjectId::new(),
            email: "".to_string(),
            password: "".to_string(),
            role: Default::default(),

            created_at: DateTime::now(),
            updated_at: DateTime::now(),
        };

        let (model, token) = generate_refresh_token_model(&jwt, &argon, &user_model).unwrap();
        verify_password(&argon, &token, &model.token);

        let token = decode_refresh_token(&jwt, &token).unwrap();
        assert_eq!(token.claims.sub, model.id);
        assert_eq!(token.claims.user_id, model.user_id);

        let (_, token) = generate_refresh_token_model_with_exp(
            &jwt,
            &argon,
            &user_model,
            current_timestamp() + Duration::seconds(-1),
        )
        .unwrap();

        let token = decode_refresh_token(&jwt, &token).unwrap();

        assert!(token.claims.is_expired());
    }

    #[test]
    pub fn test_access_token() {
        dotenvy::dotenv().unwrap();

        let jwt = JwtState::new_from_env();

        let user_model = UserModel {
            id: ObjectId::new(),
            email: "".to_string(),
            password: "".to_string(),
            role: Default::default(),

            created_at: DateTime::now(),
            updated_at: DateTime::now(),
        };

        let token = generate_access_token(&jwt, &user_model).unwrap().token;

        let token = decode_access_token(&jwt, &token).unwrap();
        assert_eq!(token.claims.sub, user_model.id);
        assert_eq!(token.claims.user_role, user_model.role);
        assert!(!token.claims.is_expired());

        let token = generate_access_token_with_exp(
            &jwt,
            &user_model,
            (current_timestamp() + Duration::seconds(-1)).unix_timestamp(),
        )
        .unwrap();

        let token = decode_access_token(&jwt, &token).unwrap();

        assert!(token.claims.is_expired());
    }
}
