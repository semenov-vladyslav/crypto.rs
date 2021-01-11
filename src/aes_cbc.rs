// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub use aead::{Error, Key, NewAead, Tag};
use aes_crate::{Aes128, Aes192, Aes256, BlockCipher, NewBlockCipher};
use block_modes::{block_padding::Pkcs7, BlockMode as _, Cbc};
use core::{
    convert::TryInto,
    marker::PhantomData,
    ops::{Add, Sub},
};
use generic_array::{
    sequence::Split,
    typenum::{Unsigned, U16, U24, U32},
    ArrayLength, GenericArray,
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

pub type NonceLength = U16;
pub type Nonce = aead::Nonce<NonceLength>;

type AesCbcPkcs7<C> = Cbc<C, Pkcs7>;
type CombinedKey<M, E> = <M as Add<E>>::Output;
type DigestOutput<D> = <D as FixedOutput>::OutputSize;

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
    C: BlockCipher + NewBlockCipher,
    D: Clone + Default + BlockInput + FixedOutput + Update + Reset,
    DigestOutput<D>: ArrayLength<u8> + Sub<T, Output = T>,
    M: ArrayLength<u8> + Add<E>,
    E: ArrayLength<u8>,
    T: ArrayLength<u8>,
    CombinedKey<M, E>: ArrayLength<u8>,
{
    pub fn padding_size(plaintext: &[u8]) -> usize {
        Self::block_size() - (plaintext.len() % Self::block_size())
    }

    fn block_size() -> usize {
        <<C as BlockCipher>::BlockSize as Unsigned>::USIZE
    }

    pub fn encrypt(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<Tag<T>, Error> {
        assert!(ciphertext.len() >= plaintext.len()); // TODO: Proper Error

        let cipher: AesCbcPkcs7<C> = self.cipher(nonce)?;
        let position: usize = plaintext.len();

        ciphertext[..plaintext.len()].copy_from_slice(plaintext);

        cipher.encrypt(ciphertext, position).map_err(|_| Error)?;

        self.compute_tag(associated_data, nonce, ciphertext)
    }

    pub fn decrypt(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
        tag: &Tag<T>,
    ) -> Result<usize, Error> {
        assert!(plaintext.len() >= ciphertext.len()); // TODO: Proper Error

        let cipher: AesCbcPkcs7<C> = self.cipher(nonce)?;
        let computed: Tag<T> = self.compute_tag(associated_data, nonce, ciphertext)?;

        if computed.ct_eq(tag).unwrap_u8() != 1 {
            return Err(Error);
        }

        plaintext[..ciphertext.len()].copy_from_slice(ciphertext);

        cipher.decrypt(plaintext).map_err(|_| Error).map(|output| output.len())
    }

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
        let key: &[u8] = &self.key[..M::USIZE];
        let mut hmac: Hmac<D> = Hmac::new_varkey(key).map_err(|_| Error)?;

        hmac.update(aad);
        hmac.update(nonce);
        hmac.update(ciphertext);
        hmac.update(&((aad.len() as u64) * 8).to_be_bytes());

        Ok(Split::split(hmac.finalize().into_bytes()).0)
    }

    fn cipher(&self, nonce: &[u8]) -> Result<AesCbcPkcs7<C>, Error> {
        let key: &[u8] = &self.key[M::USIZE..];
        let nonce: &Nonce = nonce.try_into().map_err(|_| Error)?;

        AesCbcPkcs7::new_var(key, nonce).map_err(|_| Error)
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
