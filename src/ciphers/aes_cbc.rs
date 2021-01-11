// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub use crate::aes_cbc::{Aes128CbcHmac256, Aes192CbcHmac384, Aes256CbcHmac512};
use crate::ciphers::traits::{
    consts::{U16, U24, U32, U48, U64},
    Cipher, Key, Nonce, Tag,
};

macro_rules! impl_aes_cbc {
    ($impl:ident, $name:expr, $key_len:ident, $tag_len:ident) => {
        impl Cipher for $impl {
            type KeyLength = $key_len;

            type NonceLength = $crate::aes_cbc::NonceLength;

            type TagLength = $tag_len;

            type Error = aead::Error;

            const NAME: &'static str = $name;

            fn padsize(plaintext: &[u8]) -> usize {
                Self::padding_size(plaintext)
            }

            fn encrypt(
                key: &Key<Self::KeyLength>,
                iv: &Nonce<Self::NonceLength>,
                aad: &[u8],
                ptx: &[u8],
                ctx: &mut [u8],
                tag: &mut Tag<Self::TagLength>,
            ) -> Result<(), Self::Error> {
                <Self as aead::NewAead>::new(key)
                    .encrypt(iv, aad, ptx, ctx)
                    .map(|out| {
                        tag.copy_from_slice(&out);
                    })
            }

            fn decrypt(
                key: &Key<Self::KeyLength>,
                iv: &Nonce<Self::NonceLength>,
                aad: &[u8],
                tag: &Tag<Self::TagLength>,
                ctx: &[u8],
                ptx: &mut [u8],
            ) -> Result<usize, Self::Error> {
                <Self as aead::NewAead>::new(key).decrypt(iv, aad, ctx, ptx, tag)
            }
        }
    };
}

impl_aes_cbc!(Aes128CbcHmac256, "AES-128-CBC-HMAC-256", U32, U16);
impl_aes_cbc!(Aes192CbcHmac384, "AES-192-CBC-HMAC-384", U48, U24);
impl_aes_cbc!(Aes256CbcHmac512, "AES-256-CBC-HMAC-512", U64, U32);
