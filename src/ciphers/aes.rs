// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use crate::ciphers::traits::consts::{U12, U16, U24, U32};

pub type Aes128Gcm = aes_gcm::Aes128Gcm;
impl_aead!(Aes128Gcm, "AES-128-GCM", U16, U12, U16);

pub type Aes192Gcm = aes_gcm::AesGcm<aes_gcm::aes::Aes192, U12>;
impl_aead!(Aes192Gcm, "AES-128-GCM", U24, U12, U16);

pub type Aes256Gcm = aes_gcm::Aes256Gcm;
impl_aead!(Aes256Gcm, "AES-128-GCM", U32, U12, U16);

pub mod AES_256_GCM {
    use crate::ciphers::{aes::Aes256Gcm, traits::Cipher};

    pub const KEY_LENGTH: usize = <Aes256Gcm as Cipher>::KEY_LENGTH;
    pub const IV_LENGTH: usize = <Aes256Gcm as Cipher>::NONCE_LENGTH;
    pub const TAG_LENGTH: usize = <Aes256Gcm as Cipher>::TAG_LENGTH;

    pub fn encrypt(
        key: &[u8; KEY_LENGTH],
        iv: &[u8; IV_LENGTH],
        associated_data: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8; TAG_LENGTH],
    ) -> crate::Result<()> {
        Aes256Gcm::encrypt(
            key.into(),
            iv.into(),
            associated_data,
            plaintext,
            ciphertext,
            tag.into(),
        )
    }

    pub fn decrypt(
        key: &[u8; KEY_LENGTH],
        iv: &[u8; IV_LENGTH],
        associated_data: &[u8],
        tag: &[u8; TAG_LENGTH],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> crate::Result<()> {
        Aes256Gcm::decrypt(
            key.into(),
            iv.into(),
            associated_data,
            tag.into(),
            ciphertext,
            plaintext,
        )
        .map(|_| ())
    }
}
