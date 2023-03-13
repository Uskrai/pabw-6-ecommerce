use std::str::FromStr;

use axum::{
    extract::{Path, State},
    Json,
};
use bson::oid::ObjectId;
use mongodb::Collection;
use num_bigint::BigInt;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{
    error::Error,
    util::{BigIntString, FormattedDateTime, ObjectIdString},
};

use super::auth::UserAccess;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProductModel {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub user_id: ObjectId,

    pub name: String,
    pub description: String,

    pub stock: BigInt,
    pub price: Decimal,

    pub created_at: bson::DateTime,
    pub updated_at: bson::DateTime,
    pub deleted_at: Option<bson::DateTime>,
}

#[derive(Clone)]
pub struct ProductCollection(pub Collection<ProductModel>);

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Product {
    pub id: ObjectIdString,
    pub user_id: ObjectIdString,
    pub name: String,
    pub description: String,

    pub stock: BigIntString,
    pub price: Decimal,

    pub created_at: FormattedDateTime,
    pub updated_at: FormattedDateTime,
    pub deleted_at: Option<FormattedDateTime>,
}

impl From<ProductModel> for Product {
    fn from(product: ProductModel) -> Self {
        Self {
            id: product.id.into(),
            user_id: product.user_id.into(),
            name: product.name,
            description: product.description,

            stock: product.stock.into(),
            price: product.price,

            created_at: product.created_at.into(),
            updated_at: product.updated_at.into(),
            deleted_at: product.deleted_at.map(Into::into),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IndexResponse {
    pub products: Vec<Product>,
}

pub async fn index(
    State(ProductCollection(collection)): State<ProductCollection>,
) -> Result<Json<IndexResponse>, Error> {
    let mut cursor = collection.find(None, None).await?;

    let mut products = vec![];

    while cursor.advance().await? {
        let product = cursor.deserialize_current()?;

        products.push(product.into());
    }

    Ok(Json(IndexResponse { products }))
}

pub async fn show(
    State(ProductCollection(products)): State<ProductCollection>,
    Path(product_id): Path<String>,
) -> Result<Json<Product>, Error> {
    let product_id = ObjectId::from_str(&product_id).map_err(|_| Error::NoResource)?;

    let product = products
        .find_one(
            bson::doc! {
                "_id": product_id,
            },
            None,
        )
        .await?
        .ok_or_else(|| Error::NoResource)?;

    Ok(Json(product.into()))
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateRequest {
    pub name: String,
    pub description: String,

    pub price: Decimal,
    pub stock: BigIntString,
}

pub async fn create(
    State(ProductCollection(products)): State<ProductCollection>,
    user: UserAccess,
    Json(request): Json<CreateRequest>,
) -> Result<Json<Product>, Error> {
    match user.role {
        super::auth::UserRole::Courier => return Err(Error::Forbidden),
        super::auth::UserRole::Customer | super::auth::UserRole::Admin => {}
    }

    let id = ObjectId::new();

    let model = ProductModel {
        id,
        user_id: user.id,
        name: request.name,
        description: request.description,
        stock: request.stock.into(),
        price: request.price,
        created_at: OffsetDateTime::now_utc().into(),
        updated_at: OffsetDateTime::now_utc().into(),
        deleted_at: None,
    };

    products.insert_one(&model, None).await?;

    Ok(Json(model.into()))
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UpdateRequest {
    pub name: String,
    pub description: String,

    pub stock: BigIntString,
    pub price: Decimal,
}

pub async fn update(
    user: UserAccess,
    State(ProductCollection(products)): State<ProductCollection>,
    Path(product_id): Path<String>,
    Json(request): Json<UpdateRequest>,
) -> Result<Json<Product>, Error> {
    match user.role {
        crate::api::v1::auth::UserRole::Courier => return Err(Error::Forbidden),
        crate::api::v1::auth::UserRole::Customer | crate::api::v1::auth::UserRole::Admin => {}
    }

    let product_id = ObjectId::from_str(&product_id).map_err(|_| Error::NoResource)?;

    let product = products
        .find_one(bson::doc! {"_id": product_id}, None)
        .await?
        .ok_or_else(|| Error::NoResource)?;

    match user.role {
        super::auth::UserRole::Customer => {
            if product.user_id != user.id {
                return Err(Error::Forbidden);
            }
        }
        super::auth::UserRole::Courier | super::auth::UserRole::Admin => {}
    }

    let product = ProductModel {
        name: request.name,
        description: request.description,
        stock: request.stock.into(),
        price: request.price,

        id: product.id,
        user_id: product.user_id,
        updated_at: OffsetDateTime::now_utc().into(),
        created_at: product.created_at,
        deleted_at: product.deleted_at,
    };

    products
        .update_one(
            bson::doc! {
                "_id": product_id
            },
            bson::doc! {
                "$set": bson::to_document(&product)?
            },
            None,
        )
        .await?;

    Ok(Json(product.into()))
}

pub async fn delete(
    State(ProductCollection(products)): State<ProductCollection>,
    user: UserAccess,
    Path(product_id): Path<String>,
) -> Result<(), Error> {
    match user.role {
        crate::api::v1::auth::UserRole::Courier => return Err(Error::Forbidden),
        crate::api::v1::auth::UserRole::Customer | crate::api::v1::auth::UserRole::Admin => {}
    }

    let product_id = ObjectId::from_str(&product_id).map_err(|_| Error::NoResource)?;

    let product = products
        .find_one(bson::doc! {"_id": product_id}, None)
        .await?
        .ok_or_else(|| Error::NoResource)?;

    match user.role {
        super::auth::UserRole::Customer => {
            if product.user_id != user.id {
                return Err(Error::Forbidden);
            }
        }
        super::auth::UserRole::Courier | super::auth::UserRole::Admin => {}
    };

    products
        .delete_one(bson::doc! {"_id": product_id}, None)
        .await?;

    Ok(())
}
