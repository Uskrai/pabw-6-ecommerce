use argon2::Argon2;
use axum::{
    extract::{FromRef, FromRequestParts, State},
    headers::{authorization::Bearer, Authorization, Cookie, Header, SetCookie},
    http::{request::Parts, HeaderValue},
    Json, RequestPartsExt, TypedHeader,
};
use bson::oid::ObjectId;
use mongodb::Collection;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use validator::Validate;

use crate::{
    error::{Error, UnauthorizedType},
    util::{hash_password, verify_password, FormattedDateTime, ObjectIdString},
};

use super::token::{
    create_refresh_token, decode_access_token, decode_refresh_token, generate_access_token,
    JwtState, RefreshTokenClaims, RefreshTokenCollection,
};

#[derive(Clone)]
pub struct UserCollection(pub Collection<UserModel>);

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserModel {
    #[serde(rename = "_id")]
    pub id: ObjectId,

    pub email: String,
    pub password: String,
    pub role: UserRole,

    pub created_at: bson::DateTime,
    pub updated_at: bson::DateTime,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UserRole {
    #[default]
    Customer,
    Courier,
    Admin,
}

pub struct UserAccess {
    pub id: ObjectId,
    pub role: UserRole,
}

impl UserAccess {
    pub fn from_token(jwt_state: &JwtState, token: &str) -> Result<Self, Error> {
        let token = decode_access_token(jwt_state, token)?;

        if token.claims.is_expired() {
            return Err(Error::Unauthorized(UnauthorizedType::InvalidAccessToken));
        }

        Ok(Self {
            id: token.claims.sub.0,
            role: token.claims.user_role,
        })
    }
}

#[axum::async_trait]
impl<S> FromRequestParts<S> for UserAccess
where
    JwtState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Error;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(token)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| Error::Unauthorized(UnauthorizedType::InvalidAccessToken))?;

        let jwt = JwtState::from_ref(&state);

        Self::from_token(&jwt, token.token())
    }
}

pub struct RefreshToken(String);

#[axum::async_trait]
impl<S> FromRequestParts<S> for RefreshToken {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let cookie = parts
            .extract::<TypedHeader<Cookie>>()
            .await
            .map_err(|_| Error::Unauthorized(UnauthorizedType::InvalidRefreshToken))?;

        let refresh_token = cookie
            .get("refresh_token")
            .ok_or_else(|| Error::Unauthorized(UnauthorizedType::InvalidRefreshToken))?;

        Ok(Self(refresh_token.to_string()))
    }
}

pub struct RefreshClaim(RefreshTokenClaims, String);

#[axum::async_trait]
impl<S> FromRequestParts<S> for RefreshClaim
where
    JwtState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let RefreshToken(refresh_token) = parts.extract::<RefreshToken>().await?;

        let jwt = JwtState::from_ref(state);

        let token = decode_refresh_token(&jwt, &refresh_token)
            .map_err(|_| Error::Unauthorized(UnauthorizedType::InvalidRefreshToken))?;

        Ok(Self(token.claims, refresh_token))
    }
}

impl UserModel {
    pub async fn from_id(
        id: ObjectId,
        UserCollection(users): &UserCollection,
    ) -> Result<Self, Error> {
        users
            .find_one(
                bson::doc! {
                    "_id": id
                },
                None,
            )
            .await?
            .ok_or_else(|| Error::Unauthorized(UnauthorizedType::InvalidAccessToken))
    }
}

#[axum::async_trait]
impl<S> FromRequestParts<S> for UserModel
where
    JwtState: FromRef<S>,
    UserCollection: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Error;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let access = parts.extract_with_state::<UserAccess, _>(state).await?;
        let users = UserCollection::from_ref(state);
        Self::from_id(access.id, &users).await
    }
}

#[derive(Validate, Serialize, Deserialize, Debug, Clone)]
pub struct RegisterRequest {
    #[validate(email)]
    pub email: String,

    #[validate(length(min = 8, max = 64))]
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegisterResponse {
    pub id: ObjectIdString,
    pub email: String,
    pub role: UserRole,

    pub created_at: FormattedDateTime,
    pub updated_at: FormattedDateTime,
}

impl From<UserModel> for RegisterResponse {
    fn from(value: UserModel) -> Self {
        Self {
            id: value.id.into(),
            email: value.email,
            role: value.role,
            created_at: value.created_at.into(),
            updated_at: value.updated_at.into(),
        }
    }
}

pub async fn register(
    State(UserCollection(users)): State<UserCollection>,
    State(argon): State<Argon2<'_>>,
    Json(request): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, Error> {
    let count = users
        .count_documents(
            bson::doc! {
                "email": &request.email
            },
            None,
        )
        .await?;

    if count > 0 {
        return Err(Error::MustUniqueError("email".to_string()));
    }

    let model = UserModel {
        id: ObjectId::new(),
        email: request.email,
        password: hash_password(&argon, &request.password)?,
        role: UserRole::Customer,
        created_at: OffsetDateTime::now_utc().into(),
        updated_at: OffsetDateTime::now_utc().into(),
    };
    users.insert_one(&model, None).await?;

    Ok(Json(model.into()))
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LoginResponse {
    pub refresh_token: String,
    pub access_token: String,
}

pub async fn login(
    State(UserCollection(users)): State<UserCollection>,
    State(refresh_tokens): State<RefreshTokenCollection>,
    State(jwt_state): State<JwtState>,
    State(argon): State<Argon2<'static>>,
    Json(request): Json<LoginRequest>,
) -> Result<(TypedHeader<SetCookie>, Json<LoginResponse>), Error> {
    let user = users
        .find_one(
            bson::doc! {
                "email": &request.email
            },
            None,
        )
        .await?;

    let user = match user {
        Some(user) if verify_password(&argon, &request.password, &user.password) => user,
        _ => {
            return Err(Error::Unauthorized(
                UnauthorizedType::WrongUsernameOrPassword,
            ))
        }
    };

    let refresh_token = create_refresh_token(&jwt_state, &argon, refresh_tokens, &user).await?;
    let access_token = generate_access_token(&jwt_state, &user)?;

    let header = TypedHeader(
        SetCookie::decode(
            &mut [HeaderValue::from_str(&format!(
                "refresh_token={}; HttpOnly; Secure; Path=/",
                refresh_token
            ))
            .unwrap()]
            .as_slice()
            .iter(),
        )
        .unwrap(),
    );

    Ok((
        header,
        Json(LoginResponse {
            refresh_token,
            access_token: access_token.token,
        }),
    ))
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RefreshAccessTokenResponse {
    pub access_token: String,
    pub expired_at: FormattedDateTime,
}

pub async fn refresh_access_token(
    State(UserCollection(users)): State<UserCollection>,
    State(RefreshTokenCollection(refresh_tokens)): State<RefreshTokenCollection>,
    State(jwt_state): State<JwtState>,
    State(argon): State<Argon2<'static>>,
    RefreshClaim(claim, refresh_token): RefreshClaim,
) -> Result<Json<RefreshAccessTokenResponse>, Error> {
    dbg!(&refresh_token, &claim);
    let model = refresh_tokens
        .find_one(bson::doc! { "_id": claim.sub }, None)
        .await?
        .ok_or_else(|| Error::Unauthorized(UnauthorizedType::InvalidRefreshToken))?;


    if !verify_password(&argon, &refresh_token, &model.token) {
        refresh_tokens
            .delete_one(bson::doc! { "_id": claim.sub }, None)
            .await?;
    }

    let user = users
        .find_one(bson::doc! { "_id": claim.user_id }, None)
        .await?
        .ok_or_else(|| Error::Unauthorized(UnauthorizedType::InvalidRefreshToken))?;

    let access_token = generate_access_token(&jwt_state, &user)?;

    Ok(Json(RefreshAccessTokenResponse {
        access_token: access_token.token,
        expired_at: access_token.expired_at.into(),
    }))
}
