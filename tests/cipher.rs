// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(any(feature = "aes", feature = "chacha", feature = "aes-cbc"))]

use crypto::{
    ciphers::traits::Cipher,
    test_utils::{corrupt, fresh},
};

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

    let mut ctx = vec![0; ptx.len() + C::padsize(&ptx[..])];
    let tag = C::try_encrypt(&key, &iv, &aad, &ptx, &mut ctx)?;

    assert_eq!(&ctx[..], &expected_ctx[..]);
    assert_eq!(&tag[..], &expected_tag[..]);

    let mut out = vec![0; ctx.len()];
    let len = C::try_decrypt(&key, &iv, &aad, &tag, &ctx, &mut out)?;

    assert_eq!(&out[..len], &ptx[..]);

    let mut corrupted_tag = tag.clone();
    corrupt(&mut corrupted_tag);
    assert!(C::try_decrypt(&key, &iv, &aad, &corrupted_tag, &ctx, &mut out).is_err());

    let mut corrupted_nonce = iv.clone();
    corrupt(&mut corrupted_nonce);
    assert!(C::try_decrypt(&key, &corrupted_nonce, &aad, &tag, &ctx, &mut out).is_err());

    if aad.is_empty() {
        assert!(C::try_decrypt(&key, &iv, &fresh::non_empty_bytestring(), &tag, &ctx, &mut out).is_err());
    } else {
        let mut corrupted_associated_data = aad.clone();
        corrupt(&mut corrupted_associated_data);
        assert!(C::try_decrypt(&key, &iv, &corrupted_associated_data, &tag, &ctx, &mut out).is_err());
        assert!(C::try_decrypt(&key, &iv, &fresh::bytestring(), &tag, &ctx, &mut out).is_err());
    }

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

#[cfg(feature = "aes-cbc")]
mod aes_cbc {
    use super::{test_cipher_all, TestVector};
    use crypto::ciphers::aes_cbc::{Aes128CbcHmac256, Aes192CbcHmac384, Aes256CbcHmac512};

    #[test]
    fn test_vectors_aes_128_cbc_hmac_256() {
        test_cipher_all::<Aes128CbcHmac256>(&include!("fixtures/aes_128_cbc_hmac_sha_256.rs")).unwrap();
    }

    #[test]
    fn test_vectors_aes_192_cbc_hmac_384() {
        test_cipher_all::<Aes192CbcHmac384>(&include!("fixtures/aes_192_cbc_hmac_sha_384.rs")).unwrap();
    }

    #[test]
    fn test_vectors_aes_256_cbc_hmac_512() {
        test_cipher_all::<Aes256CbcHmac512>(&include!("fixtures/aes_256_cbc_hmac_sha_512.rs")).unwrap();
    }
}

#[cfg(feature = "chacha")]
mod chacha {
    use super::{test_cipher_all, TestVector};
    use crypto::ciphers::chacha::{ChaCha20Poly1305, XChaCha20Poly1305};

    #[test]
    fn test_vectors_chacha20_poly1305() {
        test_cipher_all::<ChaCha20Poly1305>(&include!("fixtures/chacha20_poly1305.rs")).unwrap();
    }

    #[test]
    fn test_vectors_xchacha20_poly1305() {
        test_cipher_all::<XChaCha20Poly1305>(&include!("fixtures/xchacha20_poly1305.rs")).unwrap();
    }
}
