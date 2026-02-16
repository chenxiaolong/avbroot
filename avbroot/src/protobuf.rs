// SPDX-FileCopyrightText: 2026 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

#![allow(clippy::all)]
#![allow(clippy::nursery)]
#![allow(clippy::pedantic)]

pub mod build {
    pub mod tools {
        pub mod releasetools {
            include!(concat!(env!("OUT_DIR"), "/build.tools.releasetools.rs"));
        }
    }
}

pub mod chromeos_update_engine {
    include!(concat!(env!("OUT_DIR"), "/chromeos_update_engine.rs"));
}

/// Implement [`serde::Serialize`] and [`serde::Deserialize`] for prost enum
/// type and create a bridge to use with `#[serde(with = "...")]` since enum
/// fields are stored as their underlying repr. `$type` must be a fully
/// qualified type.
macro_rules! serde_derive_prost_enum {
    ($type:ty, $module:ident $(,)?) => {
        impl serde::Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                self.as_str_name().serialize(serializer)
            }
        }

        impl<'de> serde::Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct EnumVisitor;

                impl serde::de::Visitor<'_> for EnumVisitor {
                    type Value = $type;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        write!(formatter, "a string containing a valid enum variant")
                    }

                    fn visit_str<R>(self, v: &str) -> Result<Self::Value, R>
                    where
                        R: serde::de::Error,
                    {
                        match <$type>::from_str_name(v) {
                            Some(e) => Ok(e),
                            None => Err(serde::de::Error::custom(format!(
                                "invalid enum variant: {v}",
                            ))),
                        }
                    }
                }

                deserializer.deserialize_any(EnumVisitor)
            }
        }

        mod $module {
            pub fn serialize<S, T>(data: &T, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
                T: Copy + std::fmt::Display,
                $type: TryFrom<T>,
                <$type as TryFrom<T>>::Error: std::fmt::Display,
            {
                let value = <$type>::try_from(*data).map_err(|e| {
                    serde::ser::Error::custom(format!("invalid enum value: {data}: {e}"))
                })?;

                serde::Serialize::serialize(&value, serializer)
            }

            pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
            where
                D: serde::Deserializer<'de>,
                T: From<$type>,
            {
                let value: $type = serde::Deserialize::deserialize(deserializer)?;

                Ok(value.into())
            }
        }
    };
}

serde_derive_prost_enum!(
    crate::protobuf::build::tools::releasetools::ota_metadata::OtaType,
    ota_type,
);
