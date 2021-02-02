// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::borrow::Borrow;
use core::convert::{ TryFrom, TryInto, };
use core::marker::PhantomData;
use alloc::vec::Vec;

use rand_core::{
    RngCore,
    CryptoRng,
};

use curve25519_dalek::{
    digest::{
        Digest,
        generic_array::typenum::{
            U32,
            U64,
        },
    },
};

//TODO: Clean up error messages.
use crate::Error;

/// Private key, random 256 bits.
//TODO: Derive Zeroize.
pub struct SecretKey<H> {
    bytes: [u8; 32],
    digest: PhantomData<H>,
}

impl<H> From<[u8; 32]> for SecretKey<H> {
    fn from(bytes: [u8; 32]) -> Self {
        Self {
            bytes,
            digest: PhantomData,
        }
    }
}

impl<H> SecretKey<H> {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        //TODO: Use zeroize? It implements Zeroize for primitive types and arrays.
        //TODO: Or use secrecy::Secret?
        let mut bytes = [0_u8; 32];
        rng.fill_bytes(&mut bytes);
        Self {
            bytes,
            digest: PhantomData,
        }
    }
}

/// Public key, the Y coordinate of compressed Edwards point.
//TODO: Compare raw bytes or uncompressed points?
#[derive(PartialEq, Eq)]
pub struct PublicKey<H> {
    bytes: [u8; 32],
    digest: PhantomData<H>,
}

impl<H> From<&SecretKey<H>> for PublicKey<H> where
    H: Digest<OutputSize = U64>,
{
    fn from(sk: &SecretKey<H>) -> Self {
        let isk = internal::SecretKey::from(sk);
        let ipk = internal::PublicKey::from(&isk);
        Self {
            bytes: ipk.compressed.0,
            digest: PhantomData,
        }
    }
}

// Public key aggregated with H1 hash function.
pub struct AggregatedPublicKey<H1> {
    bytes: [u8; 32],
    digest1: PhantomData<H1>,
}

impl<H1> PartialEq for AggregatedPublicKey<H1> {
    fn eq(&self, other: &Self) -> bool {
        //TODO: Compare raw bytes or uncompressed points?
        self.bytes.eq(&other.bytes)
    }
}
impl<H1> Eq for AggregatedPublicKey<H1> {}

impl<H1> From<[u8; 32]> for AggregatedPublicKey<H1> {
    fn from(bytes: [u8; 32]) -> Self {
        Self {
            bytes,
            digest1: PhantomData,
        }
    }
}

impl<H1> AsRef<[u8; 32]> for AggregatedPublicKey<H1> {
    fn as_ref(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl<H1> AggregatedPublicKey<H1> where
    H1: Digest<OutputSize = U32>,
{
    pub fn aggregate<H, I>(mut pks: I) -> Result<Self, Error> where
        I: Iterator + Clone,
        I::Item: Borrow<PublicKey<H>>,
    {
        let ipks = pks
            //TODO: Use .collect::<Result<Vec<_>,_>>()?;
            .try_fold(Vec::new(), |mut v, pk| {
                pk
                    .borrow()
                    .try_into()
                    .map(|ipk| {
                        v.push(ipk);
                        v
                    })
            })?;
        Ok(internal::AggregatedPublicKey::<H1>::aggregate(ipks.iter()).into())
    }
}

// Commitment commited with H2 hash function.
pub struct Commitment {
    bytes: [u8; 64],
}

impl From<[u8; 64]> for Commitment {
    fn from(bytes: [u8; 64]) -> Self {
        Self {
            bytes,
        }
    }
}

impl AsRef<[u8; 64]> for Commitment {
    fn as_ref(&self) -> &[u8; 64] {
        &self.bytes
    }
}

pub struct EphemeralPublicKey {
    bytes: [u8; 32],
}

impl From<[u8; 32]> for EphemeralPublicKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self {
            bytes,
        }
    }
}

impl AsRef<[u8; 32]> for EphemeralPublicKey {
    fn as_ref(&self) -> &[u8; 32] {
        &self.bytes
    }
}

pub struct PartialSignature {
    bytes: [u8; 32],
}

impl From<[u8; 32]> for PartialSignature {
    fn from(bytes: [u8; 32]) -> Self {
        Self {
            bytes,
        }
    }
}

impl AsRef<[u8; 32]> for PartialSignature {
    fn as_ref(&self) -> &[u8; 32] {
        &self.bytes
    }
}

pub struct Signature<H0, H1, H2> {
    bytes: [u8; 64],
    digest0: PhantomData<H0>,
    digest1: PhantomData<H1>,
    digest2: PhantomData<H2>,
}

impl<H0, H1, H2> PartialEq for Signature<H0, H1, H2> {
    fn eq(&self, other: &Self) -> bool {
        //TODO: Compare raw bytes or corresponding scalars?
        self.bytes.eq(&other.bytes)
    }
}
impl<H0, H1, H2> Eq for Signature<H0, H1, H2> {}

pub use collect::Collect;

impl<H0, H1, H2> Signature<H0, H1, H2> where
    H0: Digest<OutputSize = U64>,
    H1: Digest<OutputSize = U32>,
    H2: Digest<OutputSize = U32>,
{
    pub fn verify(
        &self,
        apk: &AggregatedPublicKey<H1>,
        message: &[u8],
    ) -> Result<(), Error> {
        internal::verify::<H0, H1>(self.try_into()?, apk.try_into()?, message)
    }

    pub fn new<'a, H, I>(
        sk: &SecretKey<H>,
        pk: &PublicKey<H>,
        mut pks: I,
        user_index: usize,
        message: &'a [u8],
    ) -> Result<Round1State<'a, H, H0, H1, H2>, Error> where
        H: Digest<OutputSize = U64>,
        I: Iterator,
        I::Item: Borrow<PublicKey<H>>,
    {
        let isk = internal::SecretKey::from(sk);
        //TODO: Verify binding sk and pk?
        let ipk = internal::PublicKey::try_from(pk)?;
        //TODO: Use ExactSizeIterator for I and reserve pks
        let pks = pks.try_fold(Vec::new(), |mut v, pk| -> _ {
            v.push(pk.borrow().try_into()?);
            Ok(v)
        })?;
        let user_count = pks.len() + 1;
        if user_index < user_count {
            Ok(Round1State::<H, H0, H1, H2> {
                isk,
                ipk,
                pks,
                user_count,
                user_index,
                message,
                digest: PhantomData,
                digest0: PhantomData,
                digest1: PhantomData,
                digest2: PhantomData,
            })
        } else {
            Err(Error::InvalidArgumentError { alg: "Signature::new", expected: "user_index < user_count", })
        }
    }
}

pub struct Round1State<'a, H, H0, H1, H2> {
    isk: internal::SecretKey,
    ipk: internal::PublicKey,
    pks: Vec<internal::PublicKey>,
    user_count: usize,
    user_index: usize,
    message: &'a [u8],
    digest: PhantomData<H>,
    digest0: PhantomData<H0>,
    digest1: PhantomData<H1>,
    digest2: PhantomData<H2>,
}

pub type Round1Message = Commitment;

impl<'a, H, H0, H1, H2> Round1State<'a, H, H0, H1, H2> where
    H: Digest<OutputSize = U64>,
    H0: Digest<OutputSize = U64>,
    H1: Digest<OutputSize = U32>,
    H2: Digest<OutputSize = U32>,
{
    pub fn run<R: RngCore + CryptoRng>(self, rng: &mut R) -> Result<((Round1Message, Collect<internal::Commitment<H2>>), Round2State<'a, H, H0, H1, H2>), Error> {
        let (esk, (epk, cmt)) = internal::round_1::<H, H2, R>(rng, &self.isk.nonce, self.message);
        Ok(((cmt.into(), Collect::new(self.user_count, self.user_index)),
            Round2State::<'a, H, H0, H1, H2> { s1: self, esk, epk, },
        ))
    }
}

pub struct Round2State<'a, H, H0, H1, H2> {
    s1: Round1State<'a, H, H0, H1, H2>,
    esk: internal::EphemeralSecretKey,
    epk: internal::EphemeralPublicKey,
}

pub type Round2Message = EphemeralPublicKey;

impl<'a, H, H0, H1, H2> Round2State<'a, H, H0, H1, H2> where
    H: Digest<OutputSize = U64>,
    H0: Digest<OutputSize = U64>,
    H1: Digest<OutputSize = U32>,
    H2: Digest<OutputSize = U32>,
{
    pub fn run(self, cmts: Collect<internal::Commitment<H2>>) -> Result<((Round2Message, Collect<internal::EphemeralPublicKey>), Round3State<'a, H, H0, H1, H2>), Error> {
        let cmts = cmts.done()?.collect::<Vec<_>>();
        internal::round_2();
        Ok((((&self.epk).into(),
            Collect::new(self.s1.user_count, self.s1.user_index)),
            Round3State {
                s2: self,
                cmts,
            })
        )
    }
}

pub struct Round3State<'a, H, H0, H1, H2> {
    s2: Round2State<'a, H, H0, H1, H2>,
    cmts: Vec<internal::Commitment<H2>>,
}

pub type Round3Message = PartialSignature;

impl<'a, H, H0, H1, H2> Round3State<'a, H, H0, H1, H2> where
    H: Digest<OutputSize = U64>,
    H0: Digest<OutputSize = U64>,
    H1: Digest<OutputSize = U32>,
    H2: Digest<OutputSize = U32>,
{
    pub fn run(self, epks: Collect<internal::EphemeralPublicKey>) -> Result<((Round3Message, Collect<internal::PartialSignature>), Round4State<H0, H1, H2>), Error> {
        let epks = epks.done()?.collect::<Vec<_>>();
        let (apk, ps, sh) = internal::round_3::<H0, H1, H2, _, _, _>(
            self.s2.s1.user_index,
            &self.s2.s1.isk,
            &self.s2.s1.ipk,
            self.s2.s1.pks.iter(),
            self.s2.s1.message,
            &self.s2.esk,
            &self.s2.epk,
            epks.iter(),
            self.cmts.iter(),
        )?;
        Ok((((&ps).into(), Collect::new(self.s2.s1.user_count, self.s2.s1.user_index)),
            Round4State::<H0, H1, H2> {
                apk: apk.into(),
                sh,
                ps,
                digest0: PhantomData,
                digest1: PhantomData,
                digest2: PhantomData,
            })
        )
    }
}

pub struct Round4State<H0, H1, H2> {
    apk: AggregatedPublicKey<H1>,
    sh: internal::SignatureHalf,
    ps: internal::PartialSignature,
    digest0: PhantomData<H0>,
    digest1: PhantomData<H1>,
    digest2: PhantomData<H2>,
}

impl<H0, H1, H2> Round4State<H0, H1, H2> where
    H0: Digest<OutputSize = U64>,
    H1: Digest<OutputSize = U32>,
    H2: Digest<OutputSize = U32>,
{
    pub fn run(self, pss: Collect<internal::PartialSignature>) -> Result<(AggregatedPublicKey<H1>, Signature<H0, H1, H2>), Error> {
        let pss = pss.done()?;
        Ok((self.apk, internal::round_4(self.sh, self.ps, pss).into()))
    }
}

pub(crate) mod internal;
pub(crate) mod collect;

#[cfg(test)]
mod tests;
