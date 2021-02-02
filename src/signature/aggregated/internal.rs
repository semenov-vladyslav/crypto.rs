use core::borrow::Borrow;
use core::convert::TryFrom;
use core::iter::Iterator;

//TODO: Sync `Digest` trait version.
// `Digest` comes here from `curve25519_dalek`'s deps.
// In the rest of `iota-crypto` `Digest` comes from `sha2`.
// `digest` crate version can be ambiguous.
use curve25519_dalek::{
    scalar::Scalar,
    edwards::{ EdwardsPoint, CompressedEdwardsY, },
    constants,
    traits::{ Identity, VartimeMultiscalarMul, },
    digest::{
        Digest,
        //Output,
        generic_array::typenum::{
            U32,
            U64,
        },
    },
};

use super::*;
use crate::Error;

const H_DOMAIN: [u8; 0] = [];
//TODO: Implement fancy domain for H0 for prehashed or raw messages.
const H0_DOMAIN: [u8; 1] = ['0' as u8];
const H1_DOMAIN: [u8; 1] = ['1' as u8];
const H2_DOMAIN: [u8; 1] = ['2' as u8];

fn scalar_from_bits(mut bits: [u8; 32]) -> Scalar {
    //TODO: Scalar::from_bytes_mod_order(bits) or Scalar::from_canonical_bytes?
    bits[0] &= 248;
    bits[31] &= 63;
    bits[31] |= 64;
    Scalar::from_bits(bits)
}

//TODO: Reuse ed25519_dalek::SecretKey or ed25519_zebra::SigningKey or use custom secret key generation procedure?
//
// ed25519_dalek::SecretKey is 32 uniform random bytes.
// From it ExpandedSecretKey is derived, which is a Scalar and a nonce.
// Scalar requires some bit twiddling. Nonce is used for domain separaion.
//
// let secret_bytes: [u8; 32];
// let (lo, nonce) = sha512(secret_bytes);
// let sk = twiddle_bits(lo);
pub struct SecretKey {
    //TODO: Nonce/prefix is used for some reason.
    pub(crate) nonce: [u8; 32],
    //TODO: Secret scalar is derived from uniformly random bytes
    scalar: Scalar,
}

impl<H: Digest<OutputSize = U64>> From<&super::SecretKey<H>> for SecretKey {
    fn from(sk: &super::SecretKey<H>) -> Self {
        let mut h = H::new();
        h.update(H_DOMAIN);
        h.update(&sk.bytes);
        //TODO: zeroize hsk
        let hsk = h.finalize();
        let mut nonce = [0_u8; 32];
        nonce.copy_from_slice(&hsk[32..]);
        //TODO: zeroize bits
        let mut bits = [0_u8; 32];
        bits.copy_from_slice(&hsk[..32]);
        let scalar = scalar_from_bits(bits);

        Self {
            nonce,
            scalar,
        }
    }
}

//TODO: reuse ed25519_dalek::PublicKey or ed25519_zebra::VerificationKey
//
// Public key bytes is compressed edwards y coordinate of the public point.
// Not all 32 byte sequences represent a compressed edwards y coordinate.
// Public point can be restored from compressed edwards y coordinate.
//
// In ed25519-zebra a negative point is used.
pub struct PublicKey {
    pub(crate) compressed: CompressedEdwardsY,
    point: EdwardsPoint,
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.compressed.0.as_ref()
    }
}

impl From<&SecretKey> for PublicKey {
    fn from(sk: &SecretKey) -> PublicKey {
        let point = &sk.scalar * &constants::ED25519_BASEPOINT_TABLE;
        let compressed = point.compress();
        PublicKey {
            compressed,
            point,
        }
    }
}

impl<H> TryFrom<&super::PublicKey<H>> for PublicKey {
    type Error = crate::Error;
    fn try_from(pk: &super::PublicKey<H>) -> Result<PublicKey, Self::Error> {
        let compressed = CompressedEdwardsY(pk.bytes);
        let point = compressed
            .decompress()
            .ok_or(Error::ConvertError{
                from: "signature::aggregated::PublicKey",
                to: "signature::aggregated::internal::PublicKey",
            })?;
        Ok(PublicKey{ compressed, point, })
    }
}

pub struct AggregatedPublicKey<H1> {
    point: EdwardsPoint,
    digest1: PhantomData<H1>,
}

impl<H1> From<AggregatedPublicKey<H1>> for super::AggregatedPublicKey<H1> {
    fn from(apk: AggregatedPublicKey<H1>) -> Self {
        Self {
            bytes: apk.point.compress().to_bytes(),
            digest1: PhantomData,
        }
    }
}

impl<H1> TryFrom<&super::AggregatedPublicKey<H1>> for AggregatedPublicKey<H1> {
    type Error = crate::Error;
    fn try_from(apk: &super::AggregatedPublicKey<H1>) -> Result<Self, Error> {
        CompressedEdwardsY(apk.bytes.clone())
            .decompress()
            .map(|point| Self {
                point,
                digest1: PhantomData,
            })
            .ok_or(Error::ConvertError{
                from: "signature::aggregated::AggregatedPublicKey",
                to: "signature::aggregated::internal::AggregatedPublicKey",
            })
    }
}

impl<H1> AggregatedPublicKey<H1> where
    H1: Digest<OutputSize = U32>,
{
    fn scalars<I>(pks: I) -> impl Iterator<Item = Scalar> + Clone where
        I: Iterator + Clone,
        I::Item: Borrow<PublicKey>,
    {
        pks.clone().map(move |pk| {
            // Public key aggregation scalar is H1(pk_i | pk_1 | .. | pk_n)
            //TODO: Why not H1(i | H1(pk_1 | .. | pk_n))?
            let mut h1 = H1::new();
            h1.update(&H1_DOMAIN);
            //TODO: Hash user index instead of the whole public key?
            h1.update(pk.borrow());
            //TODO: Simplify the next step?
            pks.clone().for_each(|pk| h1.update(pk.borrow()));
            scalar_from_bits(h1.finalize().into())
        })
    }

    pub fn aggregate<I>(pks: I) -> Self where
        I: Iterator + Clone,
        I::Item: Borrow<PublicKey>,
    {
        let scalars = Self::scalars::<I>(pks.clone());
        // No need to use constant time multiplication.
        //TODO: Is vartime multiplication faster?
        let point = EdwardsPoint::vartime_multiscalar_mul(
            scalars, pks.map(|pk| pk.borrow().point));
        Self {
            point,
            digest1: PhantomData,
        }
    }

}

pub struct AggregatedKeyPair<H1> {
    public: AggregatedPublicKey<H1>,
    scalar: Scalar,
}

impl<H1> AggregatedKeyPair<H1> where
    H1: Digest<OutputSize = U32>,
{
    fn update<I>(h1: &mut H1, user_index: usize, user_pk: &PublicKey, pks: I) where
        I: Iterator + Clone,
        I::Item: Borrow<PublicKey>,
    {
        let user_count = pks
            .clone()
            .fold(0, |i, pk| {
                if i == user_index {
                    h1.update(user_pk);
                }
                h1.update(pk.borrow());
                i + 1
            });
        if user_count == user_index {
            h1.update(user_pk);
        }
    }

    fn scalars<'a, I>(user_index: usize, user_pk: &'a PublicKey, pks: I) -> (impl 'a + Iterator<Item = Scalar> + Clone, Scalar) where
        I: 'a + Iterator + Clone,
        I::Item: Borrow<PublicKey>,
    {
        let scalar = {
            let mut h1 = H1::new();
            h1.update(&H1_DOMAIN);
            //TODO: Hash user index instead of the whole public key?
            h1.update(user_pk);
            Self::update(&mut h1, user_index, user_pk, pks.clone());
            scalar_from_bits(h1.finalize().into())
        };

        (pks.clone().map(move |pk| {
            // Public key aggregation scalar is H1(pk_i | pk_1 | .. | pk_n)
            //TODO: Why not H1(i | H1(pk_1 | .. | pk_n))?
            let mut h1 = H1::new();
            h1.update(&H1_DOMAIN);
            //TODO: Hash user index instead of the whole public key?
            h1.update(pk.borrow());
            //TODO: Simplify the next step?
            Self::update(&mut h1, user_index, user_pk, pks.clone());
            scalar_from_bits(h1.finalize().into())
        }), scalar)
    }

    pub fn aggregate<I>(user_index: usize, user_pk: &PublicKey, pks: I) -> Result<Self, Error> where
        I: Iterator + Clone,
        I::Item: Borrow<PublicKey>,
    {
        let (scalars, scalar) = Self::scalars(user_index, user_pk, pks.clone());
        // No need to use constant time multiplication.
        //TODO: Is vartime multiplication faster?
        //TODO: Make sure to avoid copy on pk.bottow().point.
        let sum = EdwardsPoint::vartime_multiscalar_mul(
            scalars, pks.clone().map(|pk| pk.borrow().point));
        let user_point = scalar * &user_pk.point;
        let point = user_point + sum;
        Ok(Self {
            public: AggregatedPublicKey::<H1> {
                point,
                digest1: PhantomData,
            },
            scalar,
        })
    }
}

#[derive(Default)]
pub struct EphemeralSecretKey {
    scalar: Scalar,
}

impl EphemeralSecretKey {
    fn from_random_bytes(rnd: [u8; 32]) -> Self
    {
        Self {
            //TODO: mod vs bit twiddle
            scalar: Scalar::from_bytes_mod_order(rnd),
        }
    }

    fn from_random_bytes_wide(rnd: &[u8]) -> Self
    {
        let mut rnd_wide = [0_u8; 64];
        rnd_wide.copy_from_slice(rnd);
        Self {
            //TODO: mod vs bit twiddle
            scalar: Scalar::from_bytes_mod_order_wide(&rnd_wide),
        }
    }

    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self
    {
        let mut rnd = [0_u8; 32];
        rng.fill_bytes(&mut rnd);
        Self::from_random_bytes(rnd)
    }

    pub fn from_secret_nonce<H, R>(rng: &mut R, sk_nonce: &[u8], message: &[u8]) -> Self where
        H: Digest<OutputSize = U64>,
        R: RngCore + CryptoRng,
    {
        let mut z = [0_u8; 32];
        rng.fill_bytes(&mut z);
        let mut h = H::new();
        h.update(H_DOMAIN);
        h.update(sk_nonce);
        h.update(message);
        h.update(z);
        //GenericArray<U64> can't convert into [u8; 64]
        Self::from_random_bytes_wide(h.finalize().as_slice())
    }
}

#[derive(Clone)]
pub struct EphemeralPublicKey {
    point: EdwardsPoint,
}

impl Default for EphemeralPublicKey {
    fn default() -> Self {
        Self {
            point: EdwardsPoint::identity(),
        }
    }
}

impl From<&EphemeralSecretKey> for EphemeralPublicKey {
    fn from(esk: &EphemeralSecretKey) -> Self {
        Self {
            point: &esk.scalar * &constants::ED25519_BASEPOINT_TABLE,
        }
    }
}

impl From<&EphemeralPublicKey> for super::EphemeralPublicKey {
    fn from(epk: &EphemeralPublicKey) -> Self {
        Self { bytes: epk.point.compress().to_bytes(), }
    }
}

impl TryFrom<&super::EphemeralPublicKey> for EphemeralPublicKey {
    type Error = crate::Error;
    fn try_from(pk: &super::EphemeralPublicKey) -> Result<EphemeralPublicKey, Self::Error> {
        let compressed = CompressedEdwardsY(pk.bytes);
        let point = compressed
            .decompress()
            .ok_or(Error::ConvertError{
                from: "signature::aggregated::EphemeralPublicKey",
                to: "signature::aggregated::internal::EphemeralPublicKey",
            })?;
        Ok(EphemeralPublicKey{ point, })
    }
}

/*
impl From<&[u8; 32]> for EphemeralPublicKey {
    fn from(pk: &[u8; 32]) -> Self {
        Self {
        }
    }
}
 */

/// Blinding factor incapsulates random bytes used to make hash values randomized.
#[derive(Clone, Default)]
pub struct BlindingFactor {
    bytes: [u8; 32],
}

impl BlindingFactor {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0_u8; 32];
        rng.fill_bytes(&mut bytes);
        Self { bytes, }
    }
}

pub struct HashCommitment<H2> {
    bytes: [u8; 32],
    digest2: PhantomData<H2>,
}

impl<H2> Clone for HashCommitment<H2> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            digest2: PhantomData,
        }
    }
}

impl<H2> Default for HashCommitment<H2> {
    fn default() -> Self {
        Self {
            bytes: Default::default(),
            digest2: PhantomData,
        }
    }
}

impl<H2> HashCommitment<H2> where
    H2: Digest<OutputSize = U32>,
{
    pub fn commit(pk: &EphemeralPublicKey, bf: &BlindingFactor) -> Self {
        let mut h2 = H2::new();
        h2.update(H2_DOMAIN);
        h2.update(pk.point.compress().as_bytes());
        h2.update(&bf.bytes);
        Self {
            bytes: h2.finalize().into(),
            digest2: core::marker::PhantomData,
        }
    }

    pub fn verify(&self, epk: &EphemeralPublicKey, bf: &BlindingFactor) -> Result<(), Error> {
        if Self::commit(epk, bf).bytes == self.bytes {
            Ok(())
        } else {
            Err(Error::InvalidArgumentError { alg: "signature::aggregated::HashCommitment", expected: "valid commitment", })
        }
    }
}

pub type Commitment<H2> = (BlindingFactor, HashCommitment<H2>);

impl<H2> From<Commitment<H2>> for super::Commitment {
    fn from(cmt: Commitment<H2>) -> Self {
        let (bf, hc) = cmt;
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(&bf.bytes);
        bytes[32..].copy_from_slice(&hc.bytes);
        Self { bytes, }
    }
}

impl<H2> From<&super::Commitment> for Commitment<H2> {
    fn from(cmt: &super::Commitment) -> Self {
        let mut bf_bytes = [0_u8; 32];
        let mut hc_bytes = [0_u8; 32];
        bf_bytes.copy_from_slice(&cmt.bytes[..32]);
        hc_bytes.copy_from_slice(&cmt.bytes[32..]);
        (BlindingFactor{ bytes: bf_bytes, }, HashCommitment::<H2>{ bytes: hc_bytes, digest2: PhantomData, })
    }
}

// Round 1 consists of steps:
// 1. Generate ephemeral secret key (scalar) r:
//   - z <- random 256 bits
//   - h = H0(nonce | message | z)
//   - r = convert h to scalar
// 2. Calculate ephemeral public key (point) R:
//   - R = r G
// 3. Make a hash commitment t to R:
//   - b = convert R to bytes
//   - t = H2(b)
//
// TODO:
// - Why derive r in this way? r is not a commitment, z is never reveales
//   and it's never checked r is generated in this way.
//   r has the uniform random distribution.
//   nonce is already random/secret, does that mean z can have low entropy / be empty?
// - What is the correct way to derive a scalar from bytes? Is twiddling needed?
// - What is the correct way to convert a point to bytes?
pub fn round_1<H, H2, R>(rng: &mut R, sk_nonce: &[u8], message: &[u8]) -> (EphemeralSecretKey, (EphemeralPublicKey, Commitment<H2>)) where
    H: Digest<OutputSize = U64>,
    H2: Digest<OutputSize = U32>,
    R: RngCore + CryptoRng,
{
    let esk = EphemeralSecretKey::from_secret_nonce::<H, R>(rng, sk_nonce, message);
    let epk = EphemeralPublicKey::from(&esk);
    let blinding_factor = BlindingFactor::random(rng);
    //TODO: choose different hash function / domain separation
    let hash_commitment = HashCommitment::<H2>::commit(&epk, &blinding_factor);
    (esk, (epk, (blinding_factor, hash_commitment)))
}

#[derive(Clone)]
pub struct PartialSignature {
    pub(crate) scalar: Scalar,
}

impl TryFrom<&super::PartialSignature> for PartialSignature {
    type Error = crate::Error;
    fn try_from(s: &super::PartialSignature) -> Result<Self, Error> {
        Scalar::from_canonical_bytes(s.bytes.clone())
            .map(|scalar| Self { scalar, })
            .ok_or(Error::InvalidArgumentError{ alg: "PartialSignature", expected: "canonical", })
    }
}

impl From<&PartialSignature> for super::PartialSignature {
    fn from(ps: &PartialSignature) -> Self {
        Self {
            bytes: ps.scalar.to_bytes(),
        }
    }
}

pub fn round_2() {}

pub fn round_3<H0, H1, H2, I, J, K>(
    user_index: usize,
    sk: &SecretKey,
    pk: &PublicKey,
    pks: I,
    message: &[u8],
    esk: &EphemeralSecretKey,
    epk: &EphemeralPublicKey,
    epks: J,
    cmts: K,
) -> Result<(AggregatedPublicKey<H1>, PartialSignature, SignatureHalf), Error> where
    H0: Digest<OutputSize = U64>,
    H1: Digest<OutputSize = U32>,
    H2: Digest<OutputSize = U32>,
    I: Iterator + Clone,
    I::Item: Borrow<PublicKey>,
    J: Iterator + Clone,
    J::Item: Borrow<EphemeralPublicKey>,
    K: Iterator + Clone,
    K::Item: Borrow<Commitment<H2>>,
{
    // Validate commitments
    epks
        .clone()
        .zip(cmts)
        .fold(Ok(()), |v, (epk, cmt)| {
            let (bf, hc) = cmt.borrow();
            v.and(hc.verify(epk.borrow(), bf))
        })?;

    let point = epks.fold(epk.point, |sum, epk| &sum + &epk.borrow().point);
    let akp = AggregatedKeyPair::<H1>::aggregate::<I>(user_index, pk, pks)?;
    let mut h0 = H0::new();
    h0.update(H0_DOMAIN);
    h0.update(point.compress().as_bytes());
    h0.update(akp.public.point.compress().as_bytes());
    h0.update(message);
    //TODO: Why H0 must be 64 bytes output vs 32 bytes?
    //TODO: Scalar::from_hash(h0) vs scalar_from_bits(h0.finalize().into())?
    let k = Scalar::from_hash(h0);
    let xk = &k * &sk.scalar;
    let xka = &xk * &akp.scalar;
    let scalar = &esk.scalar + &xka;
    Ok((akp.public,
        PartialSignature { scalar, },
        SignatureHalf { point, },
    ))
}

pub struct SignatureHalf {
    point: EdwardsPoint,
}

pub struct Signature {
    point: EdwardsPoint,
    scalar: Scalar,
}

impl<H0, H1, H2> TryFrom<&super::Signature<H0, H1, H2>> for Signature {
    type Error = crate::Error;
    fn try_from(s: &super::Signature<H0, H1, H2>) -> Result<Self, Error> {
        //TODO: Fast verify scalars as in ed25519 scalar[31] & 240
        let mut point_bytes = [0_u8; 32];
        point_bytes.copy_from_slice(&s.bytes[..32]);
        let mut scalar_bytes = [0_u8; 32];
        scalar_bytes.copy_from_slice(&s.bytes[32..]);

        let compressed = CompressedEdwardsY(point_bytes);
        let point = compressed
            .decompress()
            .ok_or(Error::ConvertError{
                from: "signature::aggregated::Signature",
                to: "signature::aggregated::internal::Signature",
            })?;

        let scalar = Scalar::from_canonical_bytes(scalar_bytes)
            .ok_or(Error::ConvertError{
                from: "signature::aggregated::Signature",
                to: "signature::aggregated::internal::Signature",
            })?;

        Ok(Self {
            point,
            scalar,
        })
    }
}

impl<H0, H1, H2> From<Signature> for super::Signature<H0, H1, H2> {
    fn from(s: Signature) -> Self {
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(&s.point.compress().as_bytes()[..]);
        bytes[32..].copy_from_slice(&s.scalar.as_bytes()[..]);
        Self {
            bytes,
            digest0: PhantomData,
            digest1: PhantomData,
            digest2: PhantomData,
        }
    }
}

/// Aggregate the final signature out of partial signatures.
pub fn round_4<I>(sh: SignatureHalf, ps: PartialSignature, pss: I) -> Signature where
    I: Iterator,
    I::Item: Borrow<PartialSignature>,
{
    let point = sh.point;
    //TODO: Verify partial signatures?
    let scalar = pss
        .fold(ps.scalar, |scalar, ps|
              //TODO: Use UnpackedScalar::add to avoid packing and reduce in the end?
              scalar + ps.borrow().scalar
        );
    Signature { point, scalar, }
}

pub fn verify<H0, H1>(s: Signature, apk: AggregatedPublicKey<H1>, message: &[u8]) -> Result<(), Error> where
    H0: Digest<OutputSize = U64>,
{
    let mut h0 = H0::new();
    h0.update(H0_DOMAIN);
    //TODO: Save s.point bytes in order to avoid compression?
    h0.update(s.point.compress().as_bytes());
    //TODO: Save apk.point bytes in order to avoid compression?
    h0.update(apk.point.compress().as_bytes());
    h0.update(message);
    let k = Scalar::from_hash(h0);
    let ma = -apk.point;
    let point = EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &ma, &s.scalar);
    if point.compress() == s.point.compress() {
        Ok(())
    } else {
        Err(Error::SignatureError)
    }
}
