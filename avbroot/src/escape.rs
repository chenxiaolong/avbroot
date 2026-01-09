// SPDX-FileCopyrightText: 2023 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{fmt, marker::PhantomData};

use bstr::{ByteSlice, ByteVec};
use serde::{Deserializer, Serializer, de::Visitor};
use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum Error {
    #[error("Decoded string size ({actual}) does not match expected size ({expected})")]
    BadLength { expected: usize, actual: usize },
}

pub trait FromEscaped: Sized {
    type Error;

    fn from_escaped(data: &str) -> Result<Self, Self::Error>;
}

impl FromEscaped for Vec<u8> {
    type Error = Error;

    fn from_escaped(data: &str) -> Result<Self, Self::Error> {
        Ok(Self::unescape_bytes(data))
    }
}

impl<const N: usize> FromEscaped for [u8; N] {
    type Error = Error;

    fn from_escaped(data: &str) -> Result<Self, Self::Error> {
        // Wasteful allocation, but bstr doesn't expose its decoder iterator in
        // its public API.
        let decoded = Vec::<u8>::from_escaped(data)?;
        let mut buf = [0u8; N];

        if decoded.len() != buf.len() {
            return Err(Error::BadLength {
                expected: buf.len(),
                actual: decoded.len(),
            });
        }

        buf.copy_from_slice(&decoded);

        Ok(buf)
    }
}

pub fn serialize<S, T>(data: T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: AsRef<[u8]>,
{
    let s = data.as_ref().escape_bytes().to_string();
    serializer.serialize_str(&s)
}

pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromEscaped,
    <T as FromEscaped>::Error: fmt::Display,
{
    struct EscapedStrVisitor<T>(PhantomData<T>);

    impl<T> Visitor<'_> for EscapedStrVisitor<T>
    where
        T: FromEscaped,
        <T as FromEscaped>::Error: fmt::Display,
    {
        type Value = T;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "an escaped string")
        }

        fn visit_str<E>(self, data: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            FromEscaped::from_escaped(data).map_err(serde::de::Error::custom)
        }
    }

    deserializer.deserialize_str(EscapedStrVisitor(PhantomData))
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use serde::{Deserialize, Serialize};

    use super::*;

    #[test]
    fn decode_vec() {
        for s in ["", "abc", "你好", "💩", "\x00", "\t\r\n"] {
            let escaped_s = s.as_bytes().escape_bytes().to_string();
            let decoded = Vec::<u8>::from_escaped(&escaped_s).unwrap();

            assert_eq!(decoded, s.as_bytes());
        }
    }

    #[test]
    fn decode_array() {
        assert_matches!(
            <[u8; 4]>::from_escaped(r"\t\r\n"),
            Err(Error::BadLength {
                expected: 4,
                actual: 3,
            })
        );
        assert_matches!(
            <[u8; 4]>::from_escaped(r"\t\r\n\x00\x00"),
            Err(Error::BadLength {
                expected: 4,
                actual: 5,
            })
        );
        assert_matches!(
            <[u8; 4]>::from_escaped(r"\t\r\n\x00"),
            Ok(data) if data == *b"\t\r\n\x00"
        );

        assert_matches!(
            <[u8; 0]>::from_escaped(r"\t"),
            Err(Error::BadLength {
                expected: 0,
                actual: 1,
            })
        );
        assert_matches!(
            <[u8; 0]>::from_escaped(r""),
            Ok(data) if data.is_empty()
        );
    }

    #[test]
    fn round_trip_serde() {
        #[derive(Deserialize, Serialize)]
        struct TestData {
            #[serde(with = "super")]
            contents: Vec<u8>,
        }

        let mut contents = b"foo\xffbar".to_vec();
        contents.extend("💩".as_bytes());

        let data = TestData { contents };
        let serialized = toml::ser::to_string(&data).unwrap();

        assert_eq!(serialized, "contents = 'foo\\xFFbar💩'\n");

        let new_data: TestData = toml::de::from_str(&serialized).unwrap();
        assert_eq!(data.contents, new_data.contents);
    }
}
