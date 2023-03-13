use std::str::FromStr;

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use bson::oid::ObjectId;
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::Error;

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct ObjectIdString(#[serde(with = "object_id_string")] pub ObjectId);

impl From<ObjectId> for ObjectIdString {
    fn from(value: ObjectId) -> Self {
        Self(value)
    }
}

impl std::ops::Deref for ObjectIdString {
    type Target = ObjectId;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for ObjectIdString {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl std::cmp::PartialEq for ObjectIdString {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl std::cmp::Eq for ObjectIdString {}

impl std::cmp::PartialEq<ObjectId> for ObjectIdString {
    fn eq(&self, other: &ObjectId) -> bool {
        self.0 == *other
    }
}

impl From<ObjectIdString> for bson::Bson {
    fn from(value: ObjectIdString) -> Self {
        value.0.into()
    }
}

mod object_id_string {
    use bson::oid::ObjectId;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(id: &ObjectId, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&id.to_string())
    }

    // The signature of a deserialize_with function must follow the pattern:
    //
    //    fn deserialize<'de, D>(D) -> Result<T, D::Error>
    //    where
    //        D: Deserializer<'de>
    //
    // although it may also be generic over the output types T.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<ObjectId, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FormattedDateTime(#[serde(with = "time::serde::rfc3339")] OffsetDateTime);

impl From<bson::DateTime> for FormattedDateTime {
    fn from(value: bson::DateTime) -> Self {
        Self(value.into())
    }
}

impl From<OffsetDateTime> for FormattedDateTime {
    fn from(value: OffsetDateTime) -> Self {
        Self(value)
    }
}

pub fn verify_password(argon: &Argon2, password: &str, hashed: &str) -> bool {
    let hashed = match PasswordHash::new(hashed) {
        Ok(hashed) => hashed,
        Err(_) => return false,
    };

    argon.verify_password(password.as_bytes(), &hashed).is_ok()
}

pub fn hash_password(argon: &Argon2, password: &str) -> Result<String, Error> {
    let salt = password_hash::SaltString::generate(&mut password_hash::rand_core::OsRng);

    argon
        .hash_password(password.as_bytes(), &salt)
        .map(|it| it.to_string())
        .map_err(Into::into)
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct BigIntString(pub BigInt);

impl From<BigInt> for BigIntString {
    fn from(value: BigInt) -> Self {
        Self(value)
    }
}

impl From<BigIntString> for BigInt {
    fn from(value: BigIntString) -> Self {
        value.0
    }
}

impl Serialize for BigIntString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for BigIntString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        pub struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = BigIntString;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string of integer or integer")
            }

            fn visit_i8<E>(self, v: i8) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(BigInt::from(v).into())
            }

            fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(BigInt::from(v).into())
            }

            fn visit_i16<E>(self, v: i16) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(BigInt::from(v).into())
            }

            fn visit_u16<E>(self, v: u16) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(BigInt::from(v).into())
            }

            fn visit_i32<E>(self, v: i32) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(BigInt::from(v).into())
            }

            fn visit_u32<E>(self, v: u32) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(BigInt::from(v).into())
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(BigInt::from(v).into())
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(BigInt::from(v).into())
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                BigInt::from_str(v)
                    .map(Into::into)
                    .map_err(serde::de::Error::custom)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&v)
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}
