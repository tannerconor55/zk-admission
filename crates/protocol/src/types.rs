use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Exactly 64 bytes.
///
/// V1 uses this for Ed25519 signatures.
///
/// The exact Ed25519 implementation and verification semantics remain a
/// protocol-freeze item.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SignatureV1(pub [u8; 64]);

impl SignatureV1 {
    pub const LEN: usize = 64;

    pub fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl Serialize for SignatureV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for SignatureV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SignatureVisitor;

        impl<'de> serde::de::Visitor<'de> for SignatureVisitor {
            type Value = SignatureV1;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("exactly 64 signature bytes")
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value.len() != 64 {
                    return Err(E::invalid_length(value.len(), &self));
                }

                let mut bytes = [0u8; 64];
                bytes.copy_from_slice(value);

                Ok(SignatureV1(bytes))
            }

            fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_bytes(&value)
            }
        }

        deserializer.deserialize_bytes(SignatureVisitor)
    }
}
