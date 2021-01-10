// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub use aead::{Aead, NewAead, Payload};
use aead::{Error, Key, Nonce, Tag};
use aes_crate::{
    cipher::generic_array::{
        sequence::Split,
        typenum::{Unsigned, U0, U16, U24, U32},
        ArrayLength, GenericArray,
    },
    Aes128, Aes192, Aes256, BlockCipher, NewBlockCipher,
};
use alloc::vec::Vec;
use block_modes::{block_padding::Pkcs7, BlockMode as _, Cbc};
use core::{
    marker::PhantomData,
    ops::{Add, Sub},
};
use hmac_::{Hmac, Mac as _, NewMac as _};
use sha2::{
    digest::{BlockInput, FixedOutput, Reset, Update},
    Sha256, Sha384, Sha512,
};
use subtle::ConstantTimeEq as _;

/// AES-CBC using 128-bit key and HMAC SHA-256.
pub type Aes128CbcHmac256 = AesCbc<Aes128, Sha256, U16, U16, U16>;

/// AES-CBC using 192-bit key and HMAC SHA-384.
pub type Aes192CbcHmac384 = AesCbc<Aes192, Sha384, U24, U24, U24>;

/// AES-CBC using 256-bit key and HMAC SHA-512.
pub type Aes256CbcHmac512 = AesCbc<Aes256, Sha512, U32, U32, U32>;

type CombinedKey<M, E> = <M as Add<E>>::Output;
type AesCbcPkcs7<C> = Cbc<C, Pkcs7>;

/// AES in Cipher Block Chaining mode with PKCS #7 padding and HMAC
///
/// See [RFC7518#Section-5.2](https://tools.ietf.org/html/rfc7518#section-5.2)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AesCbc<C, D, M, E, T>
where
    M: ArrayLength<u8> + Add<E>,
    E: ArrayLength<u8>,
    CombinedKey<M, E>: ArrayLength<u8>,
{
    key: GenericArray<u8, CombinedKey<M, E>>,
    cipher: PhantomData<C>,
    digest: PhantomData<D>,
    tag_len: PhantomData<T>,
    mac_key_len: PhantomData<M>,
    enc_key_len: PhantomData<E>,
}

impl<C, D, M, E, T> AesCbc<C, D, M, E, T>
where
    M: ArrayLength<u8> + Add<E>,
    E: ArrayLength<u8>,
    T: Unsigned,
    CombinedKey<M, E>: ArrayLength<u8>,
{
    pub fn expand_payload(payload: &[u8]) -> Result<(&[u8], &[u8]), Error> {
        payload
            .len()
            .checked_sub(T::to_usize())
            .ok_or(Error)
            .map(|index| payload.split_at(index))
    }
}

impl<C, D, M, E, T> AesCbc<C, D, M, E, T>
where
    C: BlockCipher + NewBlockCipher,
    M: ArrayLength<u8> + Add<E>,
    E: ArrayLength<u8>,
    CombinedKey<M, E>: ArrayLength<u8>,
{
    pub fn cipher(&self, nonce: &Nonce<U16>) -> Result<AesCbcPkcs7<C>, Error> {
        AesCbcPkcs7::new_var(&self.key[M::to_usize()..], nonce).map_err(|_| Error)
    }
}

impl<C, D, M, E, T> AesCbc<C, D, M, E, T>
where
    D: Clone + Default + BlockInput + FixedOutput + Update + Reset,
    <D as FixedOutput>::OutputSize: ArrayLength<u8> + Sub<T, Output = T>,
    M: ArrayLength<u8> + Add<E>,
    E: ArrayLength<u8>,
    T: ArrayLength<u8>,
    CombinedKey<M, E>: ArrayLength<u8>,
{
    fn compute_tag(&self, aad: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Tag<T>, Error> {
        // The octet string AL is equal to the number of bits in the Additional
        // Authenticated Data A expressed as a 64-bit unsigned big-endian integer.
        //
        // A message Authentication Tag T is computed by applying HMAC to the
        // following data, in order:
        //
        //    the Additional Authenticated Data A,
        //    the Initialization Vector IV,
        //    the ciphertext E computed in the previous step, and
        //    the octet string AL defined above.
        //
        //  The string MAC_KEY is used as the MAC key. We denote the output
        //  of the MAC computed in this step as M. The first T_LEN octets of
        //  M are used as T.
        let mut hmac: Hmac<D> = Hmac::new_varkey(&self.key[..M::to_usize()]).map_err(|_| Error)?;

        hmac.update(aad);
        hmac.update(nonce);
        hmac.update(ciphertext);
        hmac.update(&((aad.len() as u64) * 8).to_be_bytes());

        Ok(Split::split(hmac.finalize().into_bytes()).0)
    }
}

impl<C, D, M, E, T> NewAead for AesCbc<C, D, M, E, T>
where
    M: ArrayLength<u8> + Add<E>,
    E: ArrayLength<u8>,
    CombinedKey<M, E>: ArrayLength<u8>,
    <CombinedKey<M, E> as ArrayLength<u8>>::ArrayType: Copy,
{
    type KeySize = CombinedKey<M, E>;

    fn new(key: &Key<Self>) -> Self {
        Self {
            key: *key,
            cipher: PhantomData,
            digest: PhantomData,
            tag_len: PhantomData,
            mac_key_len: PhantomData,
            enc_key_len: PhantomData,
        }
    }
}

impl<C, D, M, E, T> Aead for AesCbc<C, D, M, E, T>
where
    C: BlockCipher + NewBlockCipher,
    D: Clone + Default + BlockInput + FixedOutput + Update + Reset,
    <D as FixedOutput>::OutputSize: ArrayLength<u8> + Sub<T, Output = T>,
    M: ArrayLength<u8> + Add<E>,
    E: ArrayLength<u8>,
    T: ArrayLength<u8>,
    CombinedKey<M, E>: ArrayLength<u8>,
{
    type NonceSize = U16;
    type TagSize = T;
    type CiphertextOverhead = U0;

    #[allow(non_snake_case)]
    fn encrypt<'msg, 'aad>(
        &self,
        nonce: &Nonce<Self::NonceSize>,
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error> {
        // Resolve the input to a concrete type
        let payload: Payload<'msg, 'aad> = plaintext.into();

        // Encrypt the plaintext
        let mut ciphertext: Vec<u8> = self.cipher(nonce)?.encrypt_vec(payload.msg);

        // Compute the tag and append it to the ciphertext
        let tag: Tag<T> = self.compute_tag(payload.aad, nonce, &ciphertext)?;

        ciphertext.extend_from_slice(&tag[..]);

        Ok(ciphertext)
    }

    #[allow(non_snake_case)]
    fn decrypt<'msg, 'aad>(
        &self,
        nonce: &Nonce<Self::NonceSize>,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error> {
        // Resolve the input to a concrete type
        let payload: Payload<'msg, 'aad> = ciphertext.into();

        // Split the ciphertext and tag (tag is appended to ciphertext)
        let (ciphertext, tag): (&[u8], &[u8]) = Self::expand_payload(payload.msg)?;

        // Compute the tag and compare with the extracted one
        let computed: Tag<T> = self.compute_tag(payload.aad, nonce, ciphertext)?;

        if computed.ct_eq(tag).unwrap_u8() != 1 {
            return Err(Error);
        }

        // Decrypt and return the plaintext
        self.cipher(nonce)?.decrypt_vec(ciphertext).map_err(|_| Error)
    }
}
