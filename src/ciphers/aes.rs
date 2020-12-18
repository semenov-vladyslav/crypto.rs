// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

macro_rules! impl_aes {
    ($impl:ident, $key_len:expr, $iv_len:expr, $tag_len:expr $(,)?) => {
        pub const KEY_LENGTH: usize = $key_len;
        pub const IV_LENGTH: usize = $iv_len;
        pub const TAG_LENGTH: usize = $tag_len;

        pub fn encrypt(
            key: &[u8; KEY_LENGTH],
            iv: &[u8; IV_LENGTH],
            associated_data: &[u8],
            plaintext: &[u8],
            ciphertext: &mut [u8],
            tag: &mut [u8; TAG_LENGTH],
        ) -> $crate::Result<()> {
            use aes_gcm::aead::{AeadMutInPlace as _, NewAead as _};

            if plaintext.len() > ciphertext.len() {
                return Err($crate::Error::BufferSize {
                    needs: plaintext.len(),
                    has: ciphertext.len(),
                });
            }

            ciphertext.copy_from_slice(plaintext);

            let t = $impl::new(key.into())
                .encrypt_in_place_detached((iv as &[_]).into(), associated_data, ciphertext)
                .map_err(|_| $crate::Error::CipherError {
                    alg: concat!(stringify!($impl), "::encrypt"),
                })?;

            tag.copy_from_slice(&t);

            Ok(())
        }

        pub fn decrypt(
            key: &[u8; KEY_LENGTH],
            iv: &[u8; IV_LENGTH],
            associated_data: &[u8],
            tag: &[u8; TAG_LENGTH],
            ciphertext: &[u8],
            plaintext: &mut [u8],
        ) -> $crate::Result<()> {
            use aes_gcm::aead::{AeadMutInPlace as _, NewAead as _};

            if ciphertext.len() > plaintext.len() {
                return Err($crate::Error::BufferSize {
                    needs: ciphertext.len(),
                    has: plaintext.len(),
                });
            }

            plaintext.copy_from_slice(ciphertext);

            $impl::new(key.into())
                .decrypt_in_place_detached((iv as &[_]).into(), associated_data, plaintext, tag.into())
                .map_err(|_| $crate::Error::CipherError {
                    alg: concat!(stringify!($impl), "::decrypt"),
                })
        }
    };
}

pub mod AES_128_GCM {
    use aes_gcm::Aes128Gcm;

    impl_aes!(Aes128Gcm, /* key */ 16, /* iv */ 12, /* tag */ 16);
}

pub mod AES_256_GCM {
    use aes_gcm::Aes256Gcm;

    impl_aes!(Aes256Gcm, /* key */ 32, /* iv */ 12, /* tag */ 16);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestVector {
        key: &'static str,
        iv: &'static str,
        associated_data: &'static str,
        plaintext: &'static str,
        ciphertext: &'static str,
        tag: &'static str,
    }

    #[test]
    fn test_vectors_AES_256_GCM() -> crate::Result<()> {
        let tvs = [
            // https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES#GCMVS
            TestVector {
                key: "83688deb4af8007f9b713b47cfa6c73e35ea7a3aa4ecdb414dded03bf7a0fd3a",
                iv: "0b459724904e010a46901cf3",
                associated_data: "794a14ccd178c8ebfd1379dc704c5e208f9d8424",
                plaintext: "33d893a2114ce06fc15d55e454cf90c3",
                ciphertext: "cc66bee423e3fcd4c0865715e9586696",
                tag: "0fb291bd3dba94a1dfd8b286cfb97ac5",
            },
        ];

        for tv in tvs.iter() {
            let mut key = [0; AES_256_GCM::KEY_LENGTH];
            hex::decode_to_slice(tv.key, &mut key as &mut [u8]).unwrap();

            let mut iv = [0; AES_256_GCM::IV_LENGTH];
            hex::decode_to_slice(tv.iv, &mut iv as &mut [u8]).unwrap();

            let ad = hex::decode(tv.associated_data).unwrap();
            let pt = hex::decode(tv.plaintext).unwrap();
            let expected_ct = hex::decode(tv.ciphertext).unwrap();

            let mut expected_tag = [0; AES_256_GCM::TAG_LENGTH];
            hex::decode_to_slice(tv.tag, &mut expected_tag as &mut [u8]).unwrap();

            let mut ct = vec![0; pt.len()];
            let mut tag = [0; AES_256_GCM::TAG_LENGTH];
            AES_256_GCM::encrypt(&key, &iv, &ad, &pt, &mut ct, &mut tag)?;
            assert_eq!(ct, expected_ct);
            assert_eq!(tag, expected_tag);

            let mut decrypted_plain_text = vec![0; ct.len()];
            AES_256_GCM::decrypt(&key, &iv, &ad, &tag, &ct, &mut decrypted_plain_text)?;
            assert_eq!(decrypted_plain_text, pt);
        }

        Ok(())
    }
}
