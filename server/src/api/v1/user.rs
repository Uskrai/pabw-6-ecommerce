use axum::Json;

use super::auth::{RegisterResponse, UserModel};

pub async fn profile(user: UserModel) -> Json<RegisterResponse> {
    Json(user.into())
}
