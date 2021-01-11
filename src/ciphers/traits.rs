// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use aes_gcm::aes::cipher::generic_array::{typenum::Unsigned, ArrayLength, GenericArray};

pub mod consts {
    pub use aes_gcm::aes::cipher::generic_array::typenum::*;
}

pub type Key<T> = GenericArray<u8, T>;

pub type Nonce<T> = GenericArray<u8, T>;

pub type Tag<T> = GenericArray<u8, T>;

pub trait Cipher {
    /// The size of the key required by this algorithm.
    type KeyLength: ArrayLength<u8>;

    /// The size of the nonce required by this algorithm.
    type NonceLength: ArrayLength<u8>;

    /// The size of the tag produced by this algorithm.
    type TagLength: ArrayLength<u8>;

    type Error;

    /// A human-friendly identifier of this algorithm.
    const NAME: &'static str;

    const KEY_LENGTH: usize = <Self::KeyLength as Unsigned>::USIZE;

    const NONCE_LENGTH: usize = <Self::NonceLength as Unsigned>::USIZE;

    const TAG_LENGTH: usize = <Self::TagLength as Unsigned>::USIZE;

    fn padsize(_: &[u8]) -> usize {
        0
    }

    fn encrypt(
        key: &Key<Self::KeyLength>,
        iv: &Nonce<Self::NonceLength>,
        aad: &[u8],
        ptx: &[u8],
        ctx: &mut [u8],
        tag: &mut Tag<Self::TagLength>,
    ) -> Result<(), Self::Error>;

    fn decrypt(
        key: &Key<Self::KeyLength>,
        iv: &Nonce<Self::NonceLength>,
        aad: &[u8],
        tag: &Tag<Self::TagLength>,
        ctx: &[u8],
        ptx: &mut [u8],
    ) -> Result<usize, Self::Error>;

    fn try_encrypt(
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        ptx: &[u8],
        ctx: &mut [u8],
    ) -> crate::Result<Tag<Self::TagLength>> {
        let key: &Key<Self::KeyLength> = try_generic_array(key)?;
        let iv: &Nonce<Self::NonceLength> = try_generic_array(iv)?;
        let mut tag: Tag<Self::TagLength> = Default::default();

        Self::encrypt(key, iv, aad, ptx, ctx, &mut tag).map_err(|_| crate::Error::CipherError { alg: Self::NAME })?;

        Ok(tag)
    }

    fn try_decrypt(key: &[u8], iv: &[u8], aad: &[u8], tag: &[u8], ctx: &[u8], ptx: &mut [u8]) -> crate::Result<usize> {
        let key: &Key<Self::KeyLength> = try_generic_array(key)?;
        let iv: &Nonce<Self::NonceLength> = try_generic_array(iv)?;
        let tag: &Tag<Self::TagLength> = try_generic_array(tag)?;

        Self::decrypt(key, iv, aad, tag, ctx, ptx).map_err(|_| crate::Error::CipherError { alg: Self::NAME })
    }
}

#[inline(always)]
fn try_generic_array<T>(slice: &[u8]) -> crate::Result<&GenericArray<u8, T>>
where
    T: ArrayLength<u8>,
{
    if slice.len() == T::USIZE {
        Ok(slice.into())
    } else {
        Err(crate::Error::BufferSize {
            needs: T::USIZE,
            has: slice.len(),
        })
    }
}
