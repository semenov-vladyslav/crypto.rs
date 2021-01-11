// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::ciphers::traits::consts::{U12, U16, U24, U32};

pub type ChaCha20Poly1305 = chacha20poly1305::ChaCha20Poly1305;
impl_aead!(ChaCha20Poly1305, "CHACHA20-POLY1305", U32, U12, U16);

pub type XChaCha20Poly1305 = chacha20poly1305::XChaCha20Poly1305;
impl_aead!(XChaCha20Poly1305, "XCHACHA20-POLY1305", U32, U24, U16);

pub mod xchacha20poly1305 {
    use crate::ciphers::{chacha::XChaCha20Poly1305, traits::Cipher};

    pub const XCHACHA20POLY1305_KEY_SIZE: usize = <XChaCha20Poly1305 as Cipher>::KEY_LENGTH;
    pub const XCHACHA20POLY1305_NONCE_SIZE: usize = <XChaCha20Poly1305 as Cipher>::NONCE_LENGTH;
    pub const XCHACHA20POLY1305_TAG_SIZE: usize = <XChaCha20Poly1305 as Cipher>::TAG_LENGTH;

    pub fn encrypt(
        ciphertext: &mut [u8],
        tag: &mut [u8; XCHACHA20POLY1305_TAG_SIZE],
        plaintext: &[u8],
        key: &[u8; XCHACHA20POLY1305_KEY_SIZE],
        nonce: &[u8; XCHACHA20POLY1305_NONCE_SIZE],
        associated_data: &[u8],
    ) -> crate::Result<()> {
        XChaCha20Poly1305::encrypt(
            key.into(),
            nonce.into(),
            associated_data,
            plaintext,
            ciphertext,
            tag.into(),
        )
    }

    pub fn decrypt(
        plaintext: &mut [u8],
        ciphertext: &[u8],
        key: &[u8; XCHACHA20POLY1305_KEY_SIZE],
        tag: &[u8; XCHACHA20POLY1305_TAG_SIZE],
        nonce: &[u8; XCHACHA20POLY1305_NONCE_SIZE],
        associated_data: &[u8],
    ) -> crate::Result<()> {
        XChaCha20Poly1305::decrypt(
            key.into(),
            nonce.into(),
            associated_data,
            tag.into(),
            ciphertext,
            plaintext,
        )
        .map(|_| ())
    }
}
