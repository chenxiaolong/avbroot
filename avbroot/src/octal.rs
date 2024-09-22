// SPDX-FileCopyrightText: 2023 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

//! Hack to format an integer as an octal string because toml_edit can't output
//! octal-formatted integers and many other toml parsers can't parse it either.

use std::{
    fmt::{self, Octal},
    marker::PhantomData,
};

use num_traits::{Num, PrimInt};
use serde::{de::Visitor, Deserializer, Serializer};

pub fn serialize<S, T>(data: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: PrimInt + Octal,
{
    serializer.serialize_str(&format!("{data:o}"))
}

pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: PrimInt,
    <T as Num>::FromStrRadixErr: fmt::Display,
{
    struct OctalStrVisitor<T>(PhantomData<T>);

    impl<'de, T> Visitor<'de> for OctalStrVisitor<T>
    where
        T: PrimInt,
        <T as Num>::FromStrRadixErr: fmt::Display,
    {
        type Value = T;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "a string containing an octal number")
        }

        fn visit_str<E>(self, data: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            T::from_str_radix(data, 8).map_err(serde::de::Error::custom)
        }
    }

    deserializer.deserialize_str(OctalStrVisitor(PhantomData))
}
