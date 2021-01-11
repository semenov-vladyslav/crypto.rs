// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::convert::TryInto;

pub const PUBLIC_KEY_LEN: usize = 32;
pub const SECRET_KEY_LEN: usize = 32;

/// X25519 Shared Secret
pub type SharedSecret = x25519_dalek::SharedSecret;

/// X25519 Public Key
pub struct PublicKey(x25519_dalek::PublicKey);

impl PublicKey {
    /// Create a new `PublicKey` from bytes.
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        TryInto::<[u8; PUBLIC_KEY_LEN]>::try_into(bytes)
            .map(Into::into)
            .map(Self)
            .map_err(|_| crate::Error::ConvertError {
                from: "bytes",
                to: "X25519 Public Key"
            })
    }

    /// Returns the `PublicKey` as an array of bytes.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0.to_bytes()
    }
}

/// X25519 Secret Key
pub struct SecretKey(x25519_dalek::StaticSecret);

impl SecretKey {
    /// Generate a new random `SecretKey`.
    #[cfg(feature = "random")]
    pub fn generate() -> crate::Result<Self> {
        let mut bytes: [u8; SECRET_KEY_LEN] = [0; SECRET_KEY_LEN];

        crate::rand::fill(&mut bytes[..])?;

        Self::from_bytes(&bytes[..])
    }

    /// Create a new `SecretKey` from bytes.
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        TryInto::<[u8; SECRET_KEY_LEN]>::try_into(bytes)
            .map(Into::into)
            .map(Self)
            .map_err(|_| crate::Error::ConvertError {
                from: "bytes",
                to: "X25519 Secret Key"
            })
    }

    /// Returns the `SecretKey` as an array of bytes.
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LEN] {
        self.0.to_bytes()
    }

    /// Returns the `PublicKey` which corresponds to this `SecretKey`.
    pub fn public_key(&self) -> PublicKey {
        PublicKey((&self.0).into())
    }

    /// Computes a Diffie-Hellman `SharedSecret` with the given `PublicKey`.
    pub fn diffie_hellman(&self, public: &PublicKey) -> SharedSecret {
        self.0.diffie_hellman(&public.0)
    }
}
