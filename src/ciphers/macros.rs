// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

macro_rules! impl_aead {
  ($impl:ident, $name:expr, $key_len:ident, $nonce_len:ident, $tag_len:ident) => {
    impl $crate::ciphers::traits::Cipher for $impl {
      type KeyLength = $key_len;

      type NonceLength = $nonce_len;

      type TagLength = $tag_len;

      type Error = $crate::Error;

      const NAME: &'static str = $name;

      fn encrypt(
        key: &$crate::ciphers::traits::Key<Self::KeyLength>,
        iv: &$crate::ciphers::traits::Nonce<Self::NonceLength>,
        aad: &[u8],
        ptx: &[u8],
        ctx: &mut [u8],
        tag: &mut $crate::ciphers::traits::Tag<Self::TagLength>,
      ) -> Result<(), Self::Error> {
        use aead::{AeadInPlace, NewAead};

        if ptx.len() > ctx.len() {
            return Err($crate::Error::BufferSize { needs: ptx.len(), has: ctx.len() });
        }

        if tag.len() != Self::TAG_LENGTH {
            return Err($crate::Error::BufferSize { needs: Self::TAG_LENGTH, has: tag.len() });
        }

        ctx[..ptx.len()].copy_from_slice(ptx);

        let out: $crate::ciphers::traits::Tag<Self::TagLength> = Self::new(key)
            .encrypt_in_place_detached(iv, aad, ctx)
            .map_err(|_| $crate::Error::CipherError { alg: Self::NAME })?;

        tag.copy_from_slice(&out);

        Ok(())
      }

      fn decrypt(
        key: &$crate::ciphers::traits::Key<Self::KeyLength>,
        iv: &$crate::ciphers::traits::Nonce<Self::NonceLength>,
        aad: &[u8],
        tag: &$crate::ciphers::traits::Tag<Self::TagLength>,
        ctx: &[u8],
        ptx: &mut [u8],
      ) -> Result<usize, Self::Error> {
        use aead::{AeadInPlace, NewAead};

        if ctx.len() > ptx.len() {
            return Err($crate::Error::BufferSize { needs: ctx.len(), has: ptx.len() });
        }

        ptx[..ctx.len()].copy_from_slice(ctx);

        Self::new(key)
            .decrypt_in_place_detached(iv, aad, ptx, tag)
            .map_err(|_| $crate::Error::CipherError { alg: Self::NAME })?;

        Ok(ctx.len())
      }
    }
  };
}
