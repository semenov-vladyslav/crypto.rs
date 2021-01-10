// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "aes-cbc")]

use crypto::aes_cbc::{Aead, Aes128CbcHmac256, Aes192CbcHmac384, Aes256CbcHmac512, NewAead, Payload};

#[allow(non_snake_case)]
struct TestVector {
    K: &'static [u8],
    P: &'static [u8],
    IV: &'static [u8],
    A: &'static [u8],
    E: &'static [u8],
    T: &'static [u8],
}

macro_rules! test_aes_cbc {
    ($impl:ident, $tvs:expr) => {{
        for tv in $tvs {
            let aes: $impl = $impl::new(tv.K.into());
            let payload: Payload = Payload { msg: tv.P, aad: tv.A };
            let output: Vec<u8> = aes.encrypt(tv.IV.into(), payload).unwrap();
            let (ciphertext, tag): (&[u8], &[u8]) = $impl::expand_payload(&output).unwrap();

            assert_eq!(tv.E, ciphertext);
            assert_eq!(tv.T, tag);

            let payload: Payload = Payload {
                msg: &output,
                aad: tv.A,
            };
            let output: Vec<u8> = aes.decrypt(tv.IV.into(), payload).unwrap();

            assert_eq!(tv.P, output);
        }
    }};
}

#[test]
fn test_aes_128_cbc_hmac_sha_256() {
    test_aes_cbc!(Aes128CbcHmac256, &include!("fixtures/aes_128_cbc_hmac_sha_256.rs"));
}

#[test]
fn test_aes_192_cbc_hmac_sha_384() {
    test_aes_cbc!(Aes192CbcHmac384, &include!("fixtures/aes_192_cbc_hmac_sha_384.rs"));
}

#[test]
fn test_aes_256_cbc_hmac_sha_512() {
    test_aes_cbc!(Aes256CbcHmac512, &include!("fixtures/aes_256_cbc_hmac_sha_512.rs"));
}
