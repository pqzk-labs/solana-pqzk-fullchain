//! Cryptography: on-chain SLH-DSA (SHA2-128s) + STARK verifier (Winterfell 0.12).
//!
//! AIR: affine counter x_{t+1} = x_t + inc, with x_0 = seed, x_last = seed + inc*(n-1).
//! Public inputs (seed, inc) are derived from SHA-256(cipher) in finalize::handle_verify_stark.
//! Security: AcceptableOptions::MinConjecturedSecurity(127) (≈128-bit).

use anchor_lang::prelude::msg;

// SLH-DSA re-export (SHA2-128s)
pub use slh_dsa::onchain_sha2::verify_sha2_128s as verify;
pub use slh_dsa::onchain_sha2::SIG_LEN_128S     as SIG_LEN;

// STARK verifier (Winterfell 0.12)
use winterfell::{
    verify as stark_verify, AcceptableOptions, Proof, ProofOptions, VerifierError,
    crypto::{hashers::Sha2_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement, ToElements},
    Air, AirContext, EvaluationFrame, TransitionConstraintDegree, TraceInfo, Assertion,
};
use winter_utils::{Deserializable, SliceReader};

type H  = Sha2_256<BaseElement>;
type VC = MerkleTree<H>;
type RC = DefaultRandomCoin<H>;

/// Public inputs for the AIR: (seed, inc) as base field elements.
#[derive(Clone, Copy)]
pub struct PublicInputs { pub seed: BaseElement, pub inc: BaseElement }
impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> { vec![self.seed, self.inc] }
}

/// Affine-counter AIR (x_{t+1} = x_t + inc; 2 boundary assertions).
pub struct MessageAir { ctx: AirContext<BaseElement>, pi: PublicInputs }
impl MessageAir {
    fn new(info: TraceInfo, pi: PublicInputs, opts: ProofOptions) -> Self {
        let deg = vec![TransitionConstraintDegree::new(1)];
        let ctx = AirContext::new(info, deg, 2, opts);
        Self { ctx, pi }
    }
}
impl Air for MessageAir {
    type BaseField    = BaseElement;
    type PublicInputs = PublicInputs;
    fn new(i: TraceInfo, pi: PublicInputs, o: ProofOptions) -> Self { Self::new(i, pi, o) }
    fn context(&self)->&AirContext<Self::BaseField>{&self.ctx}
    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self, f: &EvaluationFrame<E>, _:&[E], r:&mut [E]
    ){
        let inc = E::from(self.pi.inc);
        r[0] = f.next()[0] - f.current()[0] - inc;
    }
    fn get_assertions(&self)->Vec<winterfell::Assertion<Self::BaseField>>{
        let last = self.trace_length() - 1;
        vec![
            Assertion::single(0, 0, self.pi.seed),
            Assertion::single(0, last, self.pi.seed + (self.pi.inc * BaseElement::from(last as u64))),
        ]
    }
}

/// Verifies a proof for the above AIR (≈128-bit via MinConjecturedSecurity(127)).
pub fn verify_stark(bytes: &[u8], seed_u64: u64, inc_u64: u64) -> Result<(), VerifierError> {
    let proof = Proof::read_from(&mut SliceReader::new(bytes))
        .map_err(|e| VerifierError::ProofDeserializationError(format!("{e:?}")))?;
    let opts = AcceptableOptions::MinConjecturedSecurity(127);
    msg!("DBG STARK(verify): degs=1 assertions=2");
    let pi = PublicInputs { seed: BaseElement::from(seed_u64), inc: BaseElement::from(inc_u64) };
    stark_verify::<MessageAir, H, RC, VC>(proof, pi, &opts)
}
