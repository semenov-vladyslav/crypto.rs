use super::*;
use alloc::vec::Vec;

struct FixedRandom<'a>(&'a [u8]);

impl<'a> CryptoRng for FixedRandom<'a> {}

impl<'a> RngCore for FixedRandom<'a> {
    fn next_u32(&mut self) -> u32 {
        let mut dest = [0_u8; 4];
        let n = dest.len();
        dest.copy_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
        u32::from_be_bytes(dest)
    }
    fn next_u64(&mut self) -> u64 {
        let mut dest = [0_u8; 8];
        let n = dest.len();
        dest.copy_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
        u64::from_be_bytes(dest)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let n = dest.len();
        dest.copy_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        if dest.len() > self.0.len() {
            Err(core::num::NonZeroU32::new(1).unwrap().into())
        } else {
            self.fill_bytes(dest);
            Ok(())
        }
    }
}

#[test]
#[cfg(feature = "sha")]
fn test() {
    let message = [1,2,3,4];
    for n in 1..4 {
        std::println!("======");
        std::println!("test n={}", n);
        //sk[32] + cmt/bf[32] + esk/z[32]
        let rnd = (0..3).cycle().take(n * 96).collect::<Vec<_>>();
        let mut rng = FixedRandom(&rnd);
        test_sign_verify::<sha2::Sha512, sha2::Sha512, sha2::Sha256, sha2::Sha256, _>(&mut rng, n, &message);
        assert!(0 == rng.0.len(), "{}", rng.0.len());
    }
}

fn test_sign_verify<H, H0, H1, H2, R>(rng: &mut R, n: usize, message: &[u8]) where
    H: Digest<OutputSize = U64>,
    H0: Digest<OutputSize = U64>,
    H1: Digest<OutputSize = U32>,
    H2: Digest<OutputSize = U32>,
    R: RngCore + CryptoRng,
{
    // create static keypairs
    let kps = (0..n)
        .map(|i| {
            let sk = SecretKey::<H>::generate(rng);
            let pk = PublicKey::<H>::from(&sk);
            (i, sk, pk)
        })
        .collect::<Vec<_>>();
    let apk0 = AggregatedPublicKey::<H1>::aggregate(
        kps.iter().map(|(_i, _sk, pk)| pk)
    ).unwrap();

    // start new signature generation and create round 1 state
    let r1_state = kps
        .iter()
        .map(|(i, sk, pk)| {
            // other parties' public keys in relative order, not including own public key
            let pks = kps
                .iter()
                .filter_map(|(j, _s, p)| {
                    if i != j { Some(p) } else { None }
                });
            std::println!("sig new i={}", *i);
            Signature::<H0, H1, H2>::new(sk, pk, pks, *i, message).unwrap()
        });

    // run round 1
    let (r1_data, r2_state): (Vec<_>, Vec<_>) = r1_state
        .map(|s| s.run(rng).unwrap())
        .unzip();
    // get round 1 messages to be broadcasted
    let (r1_msg, mut r1_collect): (Vec<_>, Vec<_>) = r1_data
        .into_iter()
        .unzip();
    // broadcast and collect round 1 messages
    r1_collect
        .iter_mut()
        .enumerate()
        .for_each(|(i, collect)| {
            std::println!("r1 i={} c_i={}, c_m={}", i, collect.index, collect.msgs.len());
            r1_msg
                .iter()
                .enumerate()
                .for_each(|(j, msg)| {
                    if i != j {
                        std::println!("r1 c_{} u_{}", i, j);
                        collect.update(j, msg).unwrap()
                    }
                })
        });

    // run round 2
    let (r2_data, r3_state): (Vec<_>, Vec<_>) = r2_state
        .into_iter()
        .zip(r1_collect.into_iter())
        .map(|(s, c)| s.run(c).unwrap())
        .unzip();
    // get round 2 messages to be broadcasted
    let (r2_msg, mut r2_collect): (Vec<_>, Vec<_>) = r2_data
        .into_iter()
        .unzip();
    // broadcast and collect round 2 messages
    r2_collect
        .iter_mut()
        .enumerate()
        .for_each(|(i, collect)| {
            std::println!("r2 i={} c_i={}, c_m={}", i, collect.index, collect.msgs.len());
            r2_msg
                .iter()
                .enumerate()
                .for_each(|(j, msg)| {
                    if i != j {
                        std::println!("r2 c_{} u_{}", i, j);
                        collect.try_update(j, msg).unwrap()
                    }
                })
        });

    // run round 3
    let (r3_data, r4_state): (Vec<_>, Vec<_>) = r3_state
        .into_iter()
        .zip(r2_collect.into_iter())
        .map(|(s, c)| s.run(c).unwrap())
        .unzip();
    // get round 3 messages to be broadcasted
    let (r3_msg, mut r3_collect): (Vec<_>, Vec<_>) = r3_data
        .into_iter()
        .unzip();
    // broadcast and collect round 3 messages
    r3_collect
        .iter_mut()
        .enumerate()
        .for_each(|(i, collect)| {
            std::println!("r3 i={} c_i={}, c_m={}", i, collect.index, collect.msgs.len());
            r3_msg
                .iter()
                .enumerate()
                .for_each(|(j, msg)| {
                    if i != j {
                        std::println!("r3 c_{} u_{} m_{:?}", i, j, &msg.bytes);
                        collect.try_update(j, msg).unwrap()
                    }
                })
        });
    assert!(r4_state.len() == n);
    assert!(r3_collect.len() == n);

    // run round 4
    let (apk,sig): (Vec<_>, Vec<_>) = r4_state
        .into_iter()
        .zip(r3_collect.into_iter())
        .map(|(s, c)| s.run(c).unwrap())
        .unzip();
    assert!(apk.len() == n);
    assert!(sig.len() == n);
    assert!(apk.iter().all(|a| a == &apk0));
    assert!(sig.iter().all(|s| s == &sig[0]));
    sig[0].verify(&apk0, message).unwrap();
}
