// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::convert::TryInto;
use p256::elliptic_curve::sec1::EncodedPoint;
use p256::elliptic_curve::sec1::Coordinates;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::elliptic_curve::ecdh;
use signature::Signer;
use signature::Verifier;
use signature::Error as SigError;

pub type FieldBytes = p256::FieldBytes;
pub type SharedSecret = p256::ecdh::SharedSecret;

/// NIST P-256 Public Key
pub struct PublicKey(p256::PublicKey);

impl PublicKey {
  /// Create a new `PublicKey` from SEC1-encoded bytes.
  pub fn from_sec1_bytes(bytes: &[u8]) -> crate::Result<Self> {
    p256::PublicKey::from_sec1_bytes(bytes)
      .map(Self)
      .map_err(|_| crate::Error::ConvertError {
        from: "SEC1 bytes",
        to: "P-256 Public Key"
      })
  }

  pub fn from_coord(x: &[u8], y: &[u8]) -> crate::Result<Self> {
    let x: &FieldBytes = x
      .try_into()
      .map_err(|_| crate::Error::ConvertError {
        from: "bytes",
        to: "P-256 Point (x)"
      })?;

    let y: &FieldBytes = y
      .try_into()
      .map_err(|_| crate::Error::ConvertError {
        from: "bytes",
        to: "P-256 Point (y)"
      })?;

    EncodedPoint::from_affine_coordinates(x, y, false)
      .try_into()
      .map(Self)
      .map_err(|_| crate::Error::ConvertError {
        from: "Coordinates",
        to: "P-256 Public Key",
      })
  }

  pub fn to_coord(&self) -> crate::Result<(FieldBytes, FieldBytes)> {
    match self.0.to_encoded_point(false).coordinates() {
      Coordinates::Uncompressed { x, y } => Ok((*x, *y)),
      Coordinates::Identity | Coordinates::Compressed { .. } => Err(crate::Error::ConvertError {
        from: "P-256 Public Key",
        to: "Coordinates",
      }),
    }
  }

  pub fn verify(&self, message: &[u8], signature: &[u8]) -> crate::Result<()> {
    signature::Signature::from_bytes(signature)
      .and_then(|signature| Verifier::verify(self, message, &signature))
      .map_err(|_| crate::Error::SignatureError { alg: "P-256" })
  }
}

impl Verifier<Signature> for PublicKey {
  fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), SigError> {
    p256::ecdsa::VerifyingKey::from(&self.0).verify(message, &signature.0)
  }
}

/// NIST P-256 Secret Key
pub struct SecretKey(p256::SecretKey);

impl SecretKey {
  /// Generate a new random `SecretKey`.
  #[cfg(feature = "random")]
  pub fn generate() -> crate::Result<Self> {
    let mut bytes: FieldBytes = Default::default();

    crate::rand::fill(&mut bytes[..])?;

    Self::from_bytes(&bytes[..])
  }

  /// Create a new `SecretKey` from big-endian bytes.
  pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
    p256::SecretKey::from_bytes(bytes)
      .map(Self)
      .map_err(|_| crate::Error::ConvertError {
        from: "bytes",
        to: "P-256 Secret Key",
      })
  }

  /// Returns the `SecretKey` as a slice of bytes.
  pub fn to_bytes(&self) -> FieldBytes {
    self.0.to_bytes()
  }

  /// Returns the `PublicKey` which corresponds to this `SecretKey`.
  pub fn public_key(&self) -> PublicKey {
    PublicKey(self.0.public_key())
  }

  pub fn sign(&self, message: &[u8]) -> crate::Result<Signature> {
    self
      .try_sign(message)
      .map_err(|_| crate::Error::SignatureError { alg: "P-256" })
  }

  /// Computes a Diffie-Hellman `SharedSecret` with the given `PublicKey`.
  pub fn diffie_hellman(&self, public: &PublicKey) -> SharedSecret {
    ecdh::diffie_hellman(self.0.secret_scalar(), public.0.as_affine())
  }
}

impl Signer<Signature> for SecretKey {
  fn try_sign(&self, message: &[u8]) -> Result<Signature, SigError> {
    p256::ecdsa::SigningKey::from(self.0.clone()).try_sign(message).map(Signature)
  }
}

/// NIST P-256 Signature (fixed-size)
#[derive(Debug)]
pub struct Signature(p256::ecdsa::Signature);

impl AsRef<[u8]> for Signature {
  fn as_ref(&self) -> &[u8] {
    self.0.as_ref()
  }
}

impl signature::Signature for Signature {
  fn from_bytes(bytes: &[u8]) -> Result<Self, SigError> {
    p256::ecdsa::Signature::from_bytes(bytes).map(Self)
  }
}
