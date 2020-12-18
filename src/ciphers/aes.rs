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

pub mod AES_192_GCM {
    use aes_gcm::{aead::generic_array::typenum, aes::Aes192, AesGcm};

    type Aes192Gcm = AesGcm<Aes192, typenum::U12>;

    impl_aes!(Aes192Gcm, /* key */ 24, /* iv */ 12, /* tag */ 16);
}

pub mod AES_256_GCM {
    use aes_gcm::Aes256Gcm;

    impl_aes!(Aes256Gcm, /* key */ 32, /* iv */ 12, /* tag */ 16);
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! test_aes {
        ($impl:ident, $tv:expr) => {{
            let mut key = [0; $impl::KEY_LENGTH];
            hex::decode_to_slice($tv.key, &mut key).unwrap();

            let mut iv = [0; $impl::IV_LENGTH];
            hex::decode_to_slice($tv.iv, &mut iv).unwrap();

            let ad = hex::decode($tv.associated_data).unwrap();
            let pt = hex::decode($tv.plaintext).unwrap();
            let expected_ct = hex::decode($tv.ciphertext).unwrap();

            let mut expected_tag = [0; $impl::TAG_LENGTH];
            hex::decode_to_slice($tv.tag, &mut expected_tag).unwrap();

            let mut ct = vec![0; pt.len()];
            let mut tag = [0; $impl::TAG_LENGTH];
            $impl::encrypt(&key, &iv, &ad, &pt, &mut ct, &mut tag)?;
            assert_eq!(ct, expected_ct);
            assert_eq!(tag, expected_tag);

            let mut decrypted_plain_text = vec![0; ct.len()];
            $impl::decrypt(&key, &iv, &ad, &tag, &ct, &mut decrypted_plain_text)?;
            assert_eq!(decrypted_plain_text, pt);
        }};
    }

    struct TestVector {
        key: &'static str,
        iv: &'static str,
        associated_data: &'static str,
        plaintext: &'static str,
        ciphertext: &'static str,
        tag: &'static str,
    }

    #[test]
    fn test_vectors_AES_128_GCM() -> crate::Result<()> {
        let tvs = [
            // https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES#GCMVS
            TestVector {
                key: "c939cc13397c1d37de6ae0e1cb7c423c",
                iv: "b3d8cc017cbb89b39e0f67e2",
                plaintext: "c3b3c41f113a31b73d9a5cd432103069",
                associated_data: "24825602bd12a984e0092d3e448eda5f",
                ciphertext: "93fe7d9e9bfd10348a5606e5cafa7354",
                tag: "0032a1dc85f1c9786925a2e71d8272dd",
            },
            TestVector {
                key: "599eb65e6b2a2a7fcc40e51c4f6e3257",
                iv: "d407301cfa29af8525981c17",
                plaintext: "a6c9e0f248f07a3046ece12125666921",
                associated_data: "10e72efe048648d40139477a2016f8ce",
                ciphertext: "1be9359a543fd7ec3c4bc6f3c9395e89",
                tag: "e2e9c07d4c3c10a6137ca433da42f9a8",
            },
            TestVector {
                key: "2d265491712fe6d7087a5545852f4f44",
                iv: "c59868b8701fbf88e6343262",
                plaintext: "301873be69f05a84f22408aa0862d19a",
                associated_data: "67105634ac9fbf849970dc416de7ad30",
                ciphertext: "98b03c77a67831bcf16b1dd96c324e1c",
                tag: "39152e26bdc4d17e8c00493fa0be92f2",
            },
            TestVector {
                key: "1fd1e536a1c39c75fd583bc8e3372029",
                iv: "281f2552f8c34fb9b3ec85aa",
                plaintext: "f801e0839619d2c1465f0245869360da",
                associated_data: "bf12a140d86727f67b860bcf6f34e55f",
                ciphertext: "35371f2779f4140dfdb1afe79d563ed9",
                tag: "cc2b0b0f1f8b3db5dc1b41ce73f5c221",
            },
            TestVector {
                key: "7b0345f6dcf469ecf9b17efa39de5359",
                iv: "b15d6fcde5e6cf1fa99ba145",
                plaintext: "822ae01a0372b6aa46c2e5bf19db92f2",
                associated_data: "72e9cb26885154d4629e7bc91279bb19",
                ciphertext: "382e440694b0c93be8dd438e37635194",
                tag: "2fa042bff9a9cd35e343b520017841bb",
            },
            TestVector {
                key: "9db91a40020cdb07f88769309a6ac40b",
                iv: "f89e1b7e598cc2535a5c8659",
                plaintext: "f4a5003db4a4ebbc2fdb8c6756830391",
                associated_data: "70910598e7abd4f0503ecd9e21bdafb5",
                ciphertext: "40d7fc4ccc8147581f40655a07f23ee9",
                tag: "243331b48404859c66af4d7b2ee44109",
            },
            TestVector {
                key: "e2f483989b349efb59ae0a7cadc74b7a",
                iv: "3338343f9b97ebb784e75027",
                plaintext: "14d80ad66e8f5f2e6c43c3109e023a93",
                associated_data: "8b12987e600ff58df54f1f5e62e59e61",
                ciphertext: "43c2d68384d486e9788950bbb8cd8fd1",
                tag: "47d7e9144ff0ed4aa3300a944a007882",
            },
            TestVector {
                key: "5c1155084cc0ede76b3bc22e9f7574ef",
                iv: "9549e4ba69a61cad7856efc1",
                plaintext: "d1448fa852b84408e2dad8381f363de7",
                associated_data: "e98e9d9c618e46fef32660976f854ee3",
                ciphertext: "f78b60ca125218493bea1c50a2e12ef4",
                tag: "d72da7f5c6cf0bca7242c71835809449",
            },
            TestVector {
                key: "2352503740a4e1b22dcc9c002f53bd11",
                iv: "474ecccc3182e03c80a7be74",
                plaintext: "dc1c35bc78b985f2d2b1a13ce635dd69",
                associated_data: "a1bc98dacec4b6aa7fee6dfa0802f21a",
                ciphertext: "3f6f4daf6d07743b9bd2a069d3710834",
                tag: "b9c2b319adbd743f5e4ffd44304a1b5f",
            },
            TestVector {
                key: "fc1f971b514a167865341b828a4295d6",
                iv: "8851ea68d20ce0beff1e3a98",
                plaintext: "2fec17b1a9570f6651bbe9a657d82bce",
                associated_data: "ece8d5f63aebda80ebde4b750637f654",
                ciphertext: "2d27e5fa08e218f02b2e36dfad87a50e",
                tag: "eb9966774c588a31b71c4d8daa495e9e",
            },
            TestVector {
                key: "00ef3c6762be3fbab38154d902ff43b5",
                iv: "c3c1c3079cda49a75a53b3cc",
                plaintext: "be425e008e9b0c083b19a2d945c2ede9",
                associated_data: "714fa1d6904187b3c5c08a30dffc86e8",
                ciphertext: "c961a1758dcf91e539658372db18968e",
                tag: "eaf9bda9b3322f501f7329cb61c1c428",
            },
            TestVector {
                key: "2d70b9569943cc49cdef8495bdb6f0e6",
                iv: "b401d0f50880a6211fde9d9c",
                plaintext: "47a87a387944f739bd3cb03e0e8be499",
                associated_data: "592e7276bda066327f2b3cd8cc39f571",
                ciphertext: "c1b2af4d273231e71e7e066c206bf567",
                tag: "c68d8d3cf8b89e6b15f623d60fef60bd",
            },
            TestVector {
                key: "775cb7f8dc73f04fe4f9d22126bb7b57",
                iv: "81ceb17deee19b8153ff927c",
                plaintext: "8242c6c0eed6d5d1ab69cd11dbe361d0",
                associated_data: "97e07cd65065d1edc863192de98bc62c",
                ciphertext: "580f063ab1a4801d279e4ee773200abe",
                tag: "29e4d7e054a6b0a4e01133573fbe632b",
            },
            TestVector {
                key: "58ba3cb7c0a0cf5775002bf3b112d051",
                iv: "bb923c93ddca303ab131238d",
                plaintext: "6b93d2d92de05b53769ec398ab8097dc",
                associated_data: "0898ea55c0ca0594806e2dc78be15c27",
                ciphertext: "d0564006b1897bf21922fef4f6386fd4",
                tag: "3a92f3c9e3ae6b0c69dcb8868d4de27c",
            },
            TestVector {
                key: "955b761de8e98f37acb41259fa308442",
                iv: "a103db8a0825e606b70427fc",
                plaintext: "d18344c86caffc4237d2daae47817b13",
                associated_data: "c2d0d8b77a6fd03ced080e0f89de8a4b",
                ciphertext: "065d228c1289007a682aa847a36b6f30",
                tag: "fb367f47922d67c84bf47aabb2b98421",
            },
        ];

        for tv in tvs.iter() {
            test_aes!(AES_128_GCM, tv);
        }

        Ok(())
    }

    #[test]
    fn test_vectors_AES_192_GCM() -> crate::Result<()> {
        let tvs = [
            // https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES#GCMVS
            TestVector {
                key: "6f44f52c2f62dae4e8684bd2bc7d16ee7c557330305a790d",
                iv: "9ae35825d7c7edc9a39a0732",
                plaintext: "37222d30895eb95884bbbbaee4d9cae1",
                associated_data: "1b4236b846fc2a0f782881ba48a067e9",
                ciphertext: "a54b5da33fc1196a8ef31a5321bfcaeb",
                tag: "1c198086450ae1834dd6c2636796bce2",
            },
            TestVector {
                key: "a3bf9528a653fefa24722cd14ad2ab404b2a9c331043246c",
                iv: "e73189e7a0a78a62223139b5",
                plaintext: "684fa5d0de7252e14e968a547f6ae52e",
                associated_data: "f583e7ea9845476026e0ba24b53fda85",
                ciphertext: "2e0cb7ed444acebf4dff3963ce7cdcfc",
                tag: "ef7e6addcf2b0e44ce62202daba65ef1",
            },
            TestVector {
                key: "a481ece5dc83089027593a05545b3c3986afe631ed4172ab",
                iv: "ce634ec1d3b8184b6e2ca189",
                plaintext: "b3b73ddcd16676c4930f680fc84e222e",
                associated_data: "13ad169aa67a21af56924bc78dad1085",
                ciphertext: "a839d8aceeecc99143d3a10ad8beabea",
                tag: "c0589a5552065f1b122fec87a35dc781",
            },
            TestVector {
                key: "b3bdf6b27c162762d2cf011abd86553340302ebce9ced3eb",
                iv: "fff9207179d393d4af061876",
                plaintext: "a06181eec020e08d2b95cf21afd1893a",
                associated_data: "ad4875c6dc8dfd06b7a6260bc5e9bd66",
                ciphertext: "2d7407ef4a818d658bdcbfbb5a1c6005",
                tag: "850bace13ffce4f2b5fcabf3d30ed5ed",
            },
            TestVector {
                key: "99602c8aa78b8ef370d052c30485346bb9e407e5cee5fd5c",
                iv: "641315a64c75e22c5781893c",
                plaintext: "2fef30da2cdd8f753164e1a23773f572",
                associated_data: "1b9c6df27499b37cb5549c716d8390ba",
                ciphertext: "90ada6c0a1bd26d0255582748b907693",
                tag: "2166dfe6a270281e30c2432f3d17ea39",
            },
            TestVector {
                key: "b8e00e8f778093dfe3d104f66103564801210fdf55d3baeb",
                iv: "ad0e0c9ce3f2ad053ea32d3a",
                plaintext: "a5d0d57df0902a970429f4f692a63934",
                associated_data: "f739fb36033e7b5ecfaf32e53a823329",
                ciphertext: "e9187ac4b29650133b4bf373f988437d",
                tag: "f965616705582d867526615a6459f376",
            },
            TestVector {
                key: "7b808d610031c1c822ecdf2cd17e9ce6f337b7ed20bb751b",
                iv: "a6e5e761bef77c5de853a24c",
                plaintext: "4335b5212ce33d491b0efd907ffe27c2",
                associated_data: "9d2ee19495b61d364deb6bd94b46ac9c",
                ciphertext: "9d16eaa5ec019cfc2080873a0c3ff6f6",
                tag: "2be4e6fbc0e2ef667564bfc18fc673af",
            },
            TestVector {
                key: "2522508df40551a238d79b05ea73f79a2b6531538ef5e6f4",
                iv: "aad198d3a6c0384c15f54181",
                plaintext: "fc232d0b264eb52b055053adcc5f8133",
                associated_data: "efb580cbe635efbfa7e783de23e7e54c",
                ciphertext: "df432043cde58a5234719f47d87a4699",
                tag: "1bf4455b49dee655a641d5fe76165767",
            },
            TestVector {
                key: "b29488168aa933dfb6e70478448e822a62618d48f8d51bb6",
                iv: "535d6a58b03d1795c5d99d34",
                plaintext: "4ad8d2813ab55ea06ead20549334f3a1",
                associated_data: "e6d8f8ba93f55cb74724ba5352771073",
                ciphertext: "f9824cfe1b5417de1b2ea65bf176e91c",
                tag: "b9d3a4e9276df29f27b672bba11ca260",
            },
            TestVector {
                key: "77c450c7db90b8532d3a17571ae2d53ba5556aa7f6ae44c5",
                iv: "0771d0a16a167a5623dcef17",
                plaintext: "75a1e052bd113587a35e4ff80b680007",
                associated_data: "47ce3ec4207ceb2a10881cad135f6343",
                ciphertext: "4aee29956d10250b179ad1eb05dc0404",
                tag: "8dba686d72b791b3ce02a83e02d8d09e",
            },
            TestVector {
                key: "d50cabf5417dac131d5001a0b25ae051091790a67a27b417",
                iv: "1b6890d376941db5899f30f7",
                plaintext: "9a548ac8196d0db18ea1bf586496e696",
                associated_data: "cbf45723c901c987410716aaca309744",
                ciphertext: "15c207a2c7228cd4fbea4611140b1c1f",
                tag: "14fe86c9ec76dcdaf6a121edb371630e",
            },
            TestVector {
                key: "6508c6b073dbb0b2e2fc9a2fff3f81b40875b55b21f10e26",
                iv: "a7e535eeb715cf8aaa5927e7",
                plaintext: "0a98db6042fdb81031116a1b27ae0fe0",
                associated_data: "181813a84ef7b1b52f5a1f59fc4c7c9d",
                ciphertext: "d11c956d46cd0e8685f82995d611762a",
                tag: "1aeca66555f614eac29a684fd5985cd6",
            },
            TestVector {
                key: "7e22abf3fc17ada5c27bc1f1894dc105c1753f0999c58297",
                iv: "6a9076a0a9ac49f6d0529bd7",
                plaintext: "65d693d8a848c40bf3bca238770cf994",
                associated_data: "6d27d8fbca2b46f490370bf1411dd5d7",
                ciphertext: "44ea8c4c65a9785e1b35c25e619b1942",
                tag: "3944e5caed179be085182bc4505f023a",
            },
            TestVector {
                key: "be572554aff0fc53500229ad649865be7b61ea882ab04ddc",
                iv: "6d0435f45a748bbd96767797",
                plaintext: "013c511a913c7326a416a7e9397ab38a",
                associated_data: "fd3f2c0ecb88bcc04e28ce3f10a70e0e",
                ciphertext: "f04994e23ba8085c94bff11b3e714e6f",
                tag: "06e79ce6e2f201c6e46ce418fe16cb25",
            },
            TestVector {
                key: "31a3f68327a925f465df71d63a6a9ee506c667c7bc4e0cd1",
                iv: "49c3b26510fc0730cacc8859",
                plaintext: "c01b24ffe83bee9f42c2eb80e086af4a",
                associated_data: "6e967a1a4cc75de56157238c0313d123",
                ciphertext: "7f864c365360dad6f111bef7aa3b6575",
                tag: "54d3e351610c3e576f387417cd21b1d2",
            },
        ];

        for tv in tvs.iter() {
            test_aes!(AES_192_GCM, tv);
        }

        Ok(())
    }

    #[test]
    fn test_vectors_AES_256_GCM() -> crate::Result<()> {
        let tvs = [
            // https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES#GCMVS
            TestVector {
                key: "83688deb4af8007f9b713b47cfa6c73e35ea7a3aa4ecdb414dded03bf7a0fd3a",
                iv: "0b459724904e010a46901cf3",
                plaintext: "33d893a2114ce06fc15d55e454cf90c3",
                associated_data: "794a14ccd178c8ebfd1379dc704c5e208f9d8424",
                ciphertext: "cc66bee423e3fcd4c0865715e9586696",
                tag: "0fb291bd3dba94a1dfd8b286cfb97ac5",
            },
            TestVector {
                key: "013f549af9ecc2ee0259d5fc2311059cb6f10f6cd6ced3b543babe7438a88251",
                iv: "e45e759a3bfe4b652dc66d5b",
                plaintext: "79490d4d233ba594ece1142e310a9857",
                associated_data: "b5fe530a5bafce7ae79b3c15471fa68334ab378e",
                ciphertext: "619443034e4437b893a45a4c89fad851",
                tag: "6da8a991b690ff6a442087a356f8e9e3",
            },
            TestVector {
                key: "4b2815c531d2fceab303ec8bca739a97abca9373b7d415ad9d6c6fa9782518cc",
                iv: "47d647a72b3b5fe19f5d80f7",
                plaintext: "d3f6a645779e07517bd0688872e0a49b",
                associated_data: "20fd79bd0ee538f42b7264a5d098af9a30959bf5",
                ciphertext: "00be3b295899c455110a0ae833140c4d",
                tag: "d054e3997c0085e87055b79829ec3629",
            },
            TestVector {
                key: "2503b909a569f618f7eb186e4c4b81dbfe974c553e2a16a29aea6846293e1a51",
                iv: "e4fa3dc131a910c75f61a38b",
                plaintext: "188d542f8a815695c48c3a882158958c",
                associated_data: "f80edf9b51f8fd66f57ce9af5967ec028245eb6e",
                ciphertext: "4d39b5494ca12b770099a8eb0c178aca",
                tag: "adda54ad0c7f848c1c72758406b49355",
            },
            TestVector {
                key: "6c8f34f14569f625aad7b232f59fa8b187ab24fadcdbaf7d8eb45da8f914e673",
                iv: "6e2f886dd97be0e4c5bd488b",
                plaintext: "ac8aa71cfbf1e968ef5515531576e314",
                associated_data: "772ec23e49dbe1d923b1018fc2bef4b579e46241",
                ciphertext: "cb0ce70345e950b429e710c47d9c8d9b",
                tag: "9dceea98c438b1d9c154e5386180966d",
            },
            TestVector {
                key: "182fe560614e1c6adfd1566ac44856df723dcb7e171a7c5796b6d3f83ef3d233",
                iv: "8484abca6877a8622bfd2e3c",
                plaintext: "92ca46b40f2c75755a28943a68a8d81c",
                associated_data: "2618c0f7fe97772a0c97638cca238a967987c5e5",
                ciphertext: "ed1941b330f4275d05899f8677d73637",
                tag: "3fe93f1f5ffa4844963de1dc964d1996",
            },
            TestVector {
                key: "65a290b2fabe7cd5fb2f6d627e9f1f79c2c714bffb4fb86e9df3e5eab28320ed",
                iv: "5a5ed4d5592a189f0737cf47",
                plaintext: "662dda0f9c8f92bc906e90288100501c",
                associated_data: "ad1c7f7a7fb7f8fef4819c1dd1a67e007c99a87b",
                ciphertext: "8eb7cb5f0418da43f7e051c588776186",
                tag: "2b15399ee23690bbf5252fb26a01ae34",
            },
            TestVector {
                key: "7b720d31cd62966dd4d002c9ea41bcfc419e6d285dfab0023ba21b34e754cb2f",
                iv: "e1fb1f9229b451b72f89c333",
                plaintext: "1aa2948ed804f24e5d783b1bc959e086",
                associated_data: "7fdae42d0cf6a13873d3092c41dd3a19a9ea90f9",
                ciphertext: "8631d3c6b6647866b868421b6a3a548a",
                tag: "a31febbe169d8d6f391a5e60ef6243a0",
            },
            TestVector {
                key: "a2aec8f3438ab4d6d9ae566a2cf9101ad3a3cc20f83674c2e208e8ca5abac2bb",
                iv: "815c020686c52ae5ddc81680",
                plaintext: "a5ccf8b4eac22f0e1aac10b8d62cdc69",
                associated_data: "86120ce3aa81445a86d971fdb7b3b33c07b25bd6",
                ciphertext: "364c9ade7097e75f99187e5571ec2e52",
                tag: "64c322ae7a8dbf3d2407b12601e50942",
            },
            TestVector {
                key: "e5104cfcbfa30e56915d9cf79efcf064a1d4ce1919b8c20de47eab0c106d67c1",
                iv: "d1a5ec793597745c7a31b605",
                plaintext: "7b6b303381441f3fdf9a0cf79ee2e9e0",
                associated_data: "9931678430ff3aa765b871b703dfcc43fb1b8594",
                ciphertext: "425d48a76001bed9da270636be1f770b",
                tag: "76ff43a157a6748250a3fdee7446ed22",
            },
            TestVector {
                key: "f461d1b75a72d942aa096384dc20cf8514a9ad9a9720660add3f318284ca3014",
                iv: "d0495f25874e5714a1149e94",
                plaintext: "d9e4b967fdca8c8bae838a5da95d7cce",
                associated_data: "1133f372e3db22456e7ea92f29dff7f1d92864d3",
                ciphertext: "1df711e6fbcba22b0564c6e36051a3f7",
                tag: "f0563b7494d5159289b644afc4e8e397",
            },
            TestVector {
                key: "a9a98ef5076ceb45c4b60a93aeba102507f977bc9b70ded1ad7d422108cdaa65",
                iv: "54a1bc67e3a8a3e44deec232",
                plaintext: "ede93dd1eaa7c9859a0f709f86a48776",
                associated_data: "10cfef05e2cd1edd30db5c028bd936a03df03bdc",
                ciphertext: "3d3b61f553ab59a9f093cac45afa5ac0",
                tag: "7814cfc873b3398d997d8bb38ead58ef",
            },
            TestVector {
                key: "d9e17c9882600dd4d2edbeae9a224d8588ff5aa210bd902d1080a6911010c5c5",
                iv: "817f3501e977a45a9e110fd4",
                plaintext: "d74d968ea80121aea0d7a2a45cd5388c",
                associated_data: "d216284811321b7591528f0af5a3f2768429e4e8",
                ciphertext: "1587c8b00e2c197f32a21019feeee99a",
                tag: "63ea43c03d00f8ae5724589cb6f64480",
            },
            TestVector {
                key: "ec251b45cb70259846db530aff11b63be00a951827020e9d746659bef2b1fd6f",
                iv: "e41652e57b624abd84fe173a",
                plaintext: "75023f51ba81b680b44ea352c43f700c",
                associated_data: "92dd2b00b9dc6c613011e5dee477e10a6e52389c",
                ciphertext: "29274599a95d63f054ae0c9b9df3e68d",
                tag: "eb19983b9f90a0e9f556213d7c4df0f9",
            },
            TestVector {
                key: "61f71fdbe29f56bb0fdf8a9da80cef695c969a2776a88e62cb3d39fca47b18e3",
                iv: "77f1d75ab0e3a0ed9bf2b981",
                plaintext: "110a5c09703482ef1343396d0c3852d3",
                associated_data: "c882691811d3de6c927d1c9f2a0f15f782d55c21",
                ciphertext: "7e9daa4983283facd29a93037eb70bb0",
                tag: "244930965913ebe0fa7a0eb547b159fb",
            },
        ];

        for tv in tvs.iter() {
            test_aes!(AES_256_GCM, tv);
        }

        Ok(())
    }
}
