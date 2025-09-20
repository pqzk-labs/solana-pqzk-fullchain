//! Minimal STARK prover for the demo.
//! Derives seed and inc from the first 16 bytes of SHA256 of the cipher and proves the affine counter x_{t+1} = x_t + inc.
//! Uses Sha2_256 and Winterfell 0.12, uses trace length 8, and uses FRI options that target about 128 bit security.

use winterfell::{
    crypto::{hashers::Sha2_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement, ToElements},
    matrix::ColMatrix,
    Air, AirContext, Assertion, AuxRandElements, BatchingMethod, CompositionPoly,
    CompositionPolyTrace, ConstraintCompositionCoefficients, DefaultConstraintCommitment,
    DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame, FieldExtension,
    PartitionOptions, ProofOptions, Prover, StarkDomain, TraceInfo, TraceTable,
    TransitionConstraintDegree,
};
use winter_utils::Serializable;

/// Carries public inputs seed and inc derived from SHA256
#[derive(Clone, Copy)]
pub(crate) struct PublicInputs {
    pub seed: BaseElement,
    pub inc: BaseElement,
}
impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![self.seed, self.inc]
    }
}

/// Implements the affine counter AIR with two boundary assertions
pub(crate) struct MessageAir {
    ctx: AirContext<BaseElement>,
    pi: PublicInputs,
}
impl MessageAir {
    fn new(info: TraceInfo, pi: PublicInputs, opts: ProofOptions) -> Self {
        let degrees = vec![TransitionConstraintDegree::new(1)];
        let ctx = AirContext::new(info, degrees, 2, opts);
        eprintln!("[AIR] prover:new degs=1 assertions=2");
        Self { ctx, pi }
    }
}
impl Air for MessageAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    fn new(info: TraceInfo, pi: PublicInputs, opts: ProofOptions) -> Self {
        Self::new(info, pi, opts)
    }
    fn context(&self) -> &AirContext<Self::BaseField> { &self.ctx }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic: &[E],
        result: &mut [E],
    ) {
        let inc = E::from(self.pi.inc);
        result[0] = frame.next()[0] - frame.current()[0] - inc;
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last = self.trace_length() - 1;
        let asr = vec![
            Assertion::single(0, 0, self.pi.seed),
            Assertion::single(
                0,
                last,
                self.pi.seed + (self.pi.inc * BaseElement::from(last as u64)),
            ),
        ];
        eprintln!("[AIR] prover:get_assertions len={} last={}", asr.len(), last);
        asr
    }
}

/// Generates params and proof from sha256 bytes of the cipher
/// Uses bytes 0..8 for seed and 8..16 for inc in little endian; falls back if shorter
pub fn generate_proof(hash_bytes: &[u8]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let trace_len = 8usize;

    let (seed_u64, inc_u64) = if hash_bytes.len() >= 16 {
        let mut le0 = [0u8; 8];
        let mut le1 = [0u8; 8];
        le0.copy_from_slice(&hash_bytes[0..8]);
        le1.copy_from_slice(&hash_bytes[8..16]);
        (u64::from_le_bytes(le0), u64::from_le_bytes(le1))
    } else if hash_bytes.len() >= 8 {
        let mut le0 = [0u8; 8];
        le0.copy_from_slice(&hash_bytes[0..8]);
        (u64::from_le_bytes(le0), 1u64)
    } else {
        (0u64, 1u64)
    };
    let seed = BaseElement::from(seed_u64);
    let inc = BaseElement::from(inc_u64);

    let mut trace = TraceTable::new(1, trace_len);
    trace.fill(|state| state[0] = seed, |_step, state| state[0] = state[0] + inc);

    let mut inc_violations = 0usize;
    for i in 0..(trace_len - 1) {
        let cur = trace.get(0, i);
        let nxt = trace.get(0, i + 1);
        if nxt != cur + inc {
            inc_violations += 1;
        }
    }
    eprintln!("DBG Prover: inc_violations={}", inc_violations);

    let options = ProofOptions::new(
        30,
        16,
        8,
        FieldExtension::None,
        4,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );
    eprintln!("DBG Prover Options: queries=30 blowup=16 folding=4 grinding=8");

    let proof = MessageProver { options: options.clone(), seed, inc }.prove(trace)?;
    let params = options.to_bytes();
    let bytes = proof.to_bytes();
    Ok((params, bytes))
}

/// Holds prover configuration and public inputs
pub(crate) struct MessageProver {
    pub options: ProofOptions,
    pub seed: BaseElement,
    pub inc: BaseElement,
}

type H = Sha2_256<BaseElement>;
type VC = MerkleTree<H>;
type RC = DefaultRandomCoin<H>;

impl Prover for MessageProver {
    type BaseField = BaseElement;
    type Air = MessageAir;
    type Trace = TraceTable<BaseElement>;

    type HashFn = H;
    type VC = VC;
    type RandomCoin = RC;

    type TraceLde<E: FieldElement<BaseField = BaseElement>> = DefaultTraceLde<E, H, VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintCommitment<E, H, VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, MessageAir, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> PublicInputs {
        PublicInputs { seed: self.seed, inc: self.inc }
    }
    fn options(&self) -> &ProofOptions { &self.options }

    fn new_trace_lde<E: FieldElement<BaseField = BaseElement>>(
        &self,
        info: &TraceInfo,
        main: &ColMatrix<BaseElement>,
        domain: &StarkDomain<BaseElement>,
        part: PartitionOptions,
    ) -> (Self::TraceLde<E>, winterfell::TracePolyTable<E>) {
        DefaultTraceLde::new(info, main, domain, part)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = BaseElement>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<BaseElement>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = BaseElement>>(
        &self,
        air: &'a MessageAir,
        aux: Option<AuxRandElements<E>>,
        coeffs: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux, coeffs)
    }
}

#[cfg(test)]
mod tests {
    use super::generate_proof;
    /// Checks that generate_proof returns non empty artifacts
    #[test]
    fn generate_proof_basic() {
        let digest = [0u8; 32];
        let (params, proof) = generate_proof(&digest).unwrap();
        assert!(!params.is_empty());
        assert!(!proof.is_empty());
    }
}
