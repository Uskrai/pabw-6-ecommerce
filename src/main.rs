use std::{collections::HashMap, net::SocketAddr};

use axum::{extract::State, response::IntoResponse, routing, Router};
use ecommerce::app::AppState;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    dotenvy::dotenv().unwrap();
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "angkot=debug,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let app_state = AppState::new_from_env().await.unwrap();

    let api = Router::new().nest(
        "/v1",
        Router::new()
            .nest(
                "/auth",
                Router::new()
                    .route("/login", routing::post(ecommerce::api::v1::auth::login))
                    .route(
                        "/register",
                        routing::post(ecommerce::api::v1::auth::register),
                    )
                    .route(
                        "/refresh",
                        routing::post(ecommerce::api::v1::auth::refresh_access_token),
                    )
                    .route("/profile", routing::get(ecommerce::api::v1::user::profile)),
            )
            .nest(
                "/product",
                Router::new()
                    .route("/", routing::get(ecommerce::api::v1::product::index))
                    .route("/", routing::post(ecommerce::api::v1::product::create))
                    .route("/:id", routing::get(ecommerce::api::v1::product::show))
                    .route("/:id", routing::put(ecommerce::api::v1::product::update))
                    .route("/:id", routing::delete(ecommerce::api::v1::product::delete)),
            ),
    );


    let app = Router::new()
        .nest("/api", api)
        .nest(
            "/",
            Router::new().nest_service(
                "/",
                tower_http::services::fs::ServeDir::new("public")
                .fallback(tower_http::services::ServeFile::new("public/dist/index.html")),
            ),
        )
        // .route("/shared-taxi/:name", axum::routing::get(geo::shared_taxi))
        // .route("/bus/:name", axum::routing::get(geo::bus))
        // .route("/customer/shared-taxi/:name", axum::routing::get(geo::customer_shared_taxi))
        // .route("/customer/bus/:name", axum::routing::get(geo::customer_bus))
        // .nest("/api/v1", apiv1)
        .with_state(app_state)
        .layer(tower_http::trace::TraceLayer::new_for_http());

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::debug!("listening on {}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

