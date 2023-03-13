use axum::extract::FromRef;

use crate::api::v1::{
    auth::UserCollection,
    product::ProductCollection,
    token::{JwtState, RefreshTokenCollection},
};

#[derive(FromRef, Clone)]
pub struct AppState {
    argon: argon2::Argon2<'static>,
    jwt_state: JwtState,

    mongo_client: mongodb::Client,
    token_collection: RefreshTokenCollection,
    user_collection: UserCollection,
    product_collection: ProductCollection,
}

impl AppState {
    pub async fn new_from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let argon = argon2::Argon2::default();
        let jwt_state = JwtState::new_from_env();

        let mongo_url = std::env::var("MONGODB_URI")
            .expect("Cannot retreive JWT_SECRET_KEY from environment variable.");
        let mongo_client_opt = mongodb::options::ClientOptions::parse(mongo_url).await?;
        let mongo_client = mongodb::Client::with_options(mongo_client_opt)?;

        let db = mongo_client.database("ecommerce");
        Ok(Self {
            argon,
            jwt_state,

            mongo_client,
            token_collection: RefreshTokenCollection(db.collection("refresh_tokens")),
            user_collection: UserCollection(db.collection("users")),
            product_collection: ProductCollection(db.collection("products")),
        })
    }
}
