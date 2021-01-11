// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(any(feature = "aes", feature = "chacha",))]

use crypto::ciphers::traits::Cipher;

struct TestVector {
    key: &'static str,
    iv: &'static str,
    associated_data: &'static str,
    plaintext: &'static str,
    ciphertext: &'static str,
    tag: &'static str,
}

fn test_cipher_one<C: Cipher>(tv: &TestVector) -> crypto::Result<()> {
    let key = hex::decode(tv.key).unwrap();
    let iv = hex::decode(tv.iv).unwrap();
    let aad = hex::decode(tv.associated_data).unwrap();
    let ptx = hex::decode(tv.plaintext).unwrap();

    let expected_ctx = hex::decode(tv.ciphertext).unwrap();
    let expected_tag = hex::decode(tv.tag).unwrap();

    let mut ctx = vec![0; ptx.len()];

    let tag = C::try_encrypt(&key, &iv, &aad, &ptx, &mut ctx)?;

    assert_eq!(&ctx[..], &expected_ctx[..]);
    assert_eq!(&tag[..], &expected_tag[..]);

    let mut out = vec![0; ctx.len()];

    let len = C::try_decrypt(&key, &iv, &aad, &tag, &ctx, &mut out)?;

    assert_eq!(&out[..len], &ptx[..]);

    Ok(())
}

fn test_cipher_all<C: Cipher>(tvs: &[TestVector]) -> crypto::Result<()> {
    for tv in tvs {
        test_cipher_one::<C>(tv)?;
    }

    Ok(())
}

#[cfg(feature = "aes")]
mod aes {
    use super::{test_cipher_all, TestVector};
    use crypto::ciphers::aes::{Aes128Gcm, Aes192Gcm, Aes256Gcm};

    #[test]
    fn test_vectors_aes_128_gcm() {
        test_cipher_all::<Aes128Gcm>(&include!("fixtures/aes_128_gcm.rs")).unwrap();
    }

    #[test]
    fn test_vectors_aes_192_gcm() {
        test_cipher_all::<Aes192Gcm>(&include!("fixtures/aes_192_gcm.rs")).unwrap();
    }

    #[test]
    fn test_vectors_aes_256_gcm() {
        test_cipher_all::<Aes256Gcm>(&include!("fixtures/aes_256_gcm.rs")).unwrap();
    }
}
