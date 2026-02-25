// Local re-implementation of the `commitment` crate (dwallet-labs/commitment.git).
// Author: dWallet Labs, Ltd. – BSD-3-Clause-Clear (re-implementation for local build)

use core::fmt::Debug;

use crypto_bigint::{Concat, Limb};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

use group::{
    BoundedGroupElement, ComputationalSecuritySizedNumber, GroupElement, PartyID, Samplable,
    Transcribeable,
};

pub use multipedersen::MultiPedersen;
pub use pedersen::Pedersen;

pub mod multipedersen;
pub mod pedersen;

// ── Error / Result ────────────────────────────────────────────────────────────

#[derive(thiserror::Error, Clone, Debug, PartialEq)]
pub enum Error {
    #[error("invalid public parameters")]
    InvalidPublicParameters,
    #[error("group error")]
    GroupInstantiation(#[from] group::Error),
    #[error("an internal error that should never have happened and signifies a bug")]
    InternalError,
}

pub type Result<T> = std::result::Result<T, Error>;

// ── `Commitment` (hash-based commit-reveal used in DKG) ──────────────────────

/// Represents an unsigned integer sized based on the commitment size that matches the security
/// parameter, which is double in size, as collisions can be found in the root of the space.
pub type CommitmentSizedNumber = <ComputationalSecuritySizedNumber as Concat>::Output;

#[derive(PartialEq, Debug, Eq, Serialize, Deserialize, Clone, Copy)]
pub struct Commitment(CommitmentSizedNumber);

impl Commitment {
    /// Create a commitment from a transcript that holds the data and, potentially, other context.
    /// Supply a `context` to distinguish commitments between different protocols,
    /// e.g., a string containing the protocol name & round name.
    pub fn commit_transcript(
        party_id: PartyID,
        context: String,
        transcript: &mut Transcript,
        commitment_randomness: &ComputationalSecuritySizedNumber,
    ) -> Self {
        transcript.append_message(b"party ID", party_id.to_le_bytes().as_ref());

        transcript.append_message(b"context", context.as_bytes());

        transcript.append_message(
            b"commitment randomness",
            commitment_randomness.to_le_bytes().as_ref(),
        );

        let mut buf: Vec<u8> = vec![0u8; CommitmentSizedNumber::LIMBS * Limb::BYTES];
        transcript.challenge_bytes(b"commitment", buf.as_mut_slice());

        Commitment(CommitmentSizedNumber::from_le_slice(&buf))
    }
}

// ── `HomomorphicCommitmentScheme` trait ───────────────────────────────────────

/// A Homomorphic Commitment Scheme.
///
/// In a homomorphic commitment $\calM,\calR$ and $\calC$ are all Abelian groups,
/// and for all $\vec{m}_1, \vec{m}_2 \in \calM$, $\rho_1, \rho_2\in \calR$ we have:
/// $$ \Com(\vec{m}_1; \rho_1) + \Com(\vec{m}_2; \rho_2) = \Com(\vec{m}_1 + \vec{m}_2; \rho_1 + \rho_2) $$
pub trait HomomorphicCommitmentScheme<const MESSAGE_SPACE_SCALAR_LIMBS: usize>:
    PartialEq + Clone + Debug + Eq + Send + Sync
{
    /// The Message space group element of the commitment scheme
    type MessageSpaceGroupElement: BoundedGroupElement<MESSAGE_SPACE_SCALAR_LIMBS> + Samplable;
    /// The Randomness space group element of the commitment scheme
    type RandomnessSpaceGroupElement: GroupElement + Samplable;
    /// The Commitment space group element of the commitment scheme
    type CommitmentSpaceGroupElement: GroupElement;

    /// The public parameters of the commitment scheme.
    type PublicParameters: AsRef<
            GroupsPublicParameters<
                MessageSpacePublicParameters<MESSAGE_SPACE_SCALAR_LIMBS, Self>,
                RandomnessSpacePublicParameters<MESSAGE_SPACE_SCALAR_LIMBS, Self>,
                CommitmentSpacePublicParameters<MESSAGE_SPACE_SCALAR_LIMBS, Self>,
            >,
        > + Transcribeable
        + Serialize
        + for<'r> Deserialize<'r>
        + Clone
        + PartialEq
        + Eq
        + Debug
        + Send
        + Sync;

    /// Instantiate the commitment scheme from its public parameters.
    fn new(public_parameters: &Self::PublicParameters) -> Result<Self>;

    /// The commitment function.
    fn commit(
        &self,
        message: &Self::MessageSpaceGroupElement,
        randomness: &Self::RandomnessSpaceGroupElement,
    ) -> Self::CommitmentSpaceGroupElement;
}

// ── `GroupsPublicParameters` ─────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct GroupsPublicParameters<
    MessageSpacePublicParameters,
    RandomnessSpacePublicParameters,
    CommitmentSpacePublicParameters,
> {
    pub message_space_public_parameters: MessageSpacePublicParameters,
    pub randomness_space_public_parameters: RandomnessSpacePublicParameters,
    pub commitment_space_public_parameters: CommitmentSpacePublicParameters,
}

// ── `GroupsPublicParametersAccessors` trait ───────────────────────────────────

pub trait GroupsPublicParametersAccessors<
    'a,
    MessageSpacePublicParameters: 'a,
    RandomnessSpacePublicParameters: 'a,
    CommitmentSpacePublicParameters: 'a,
>:
    AsRef<
    GroupsPublicParameters<
        MessageSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
    >,
>
{
    fn message_space_public_parameters(&'a self) -> &'a MessageSpacePublicParameters {
        &self.as_ref().message_space_public_parameters
    }

    fn randomness_space_public_parameters(&'a self) -> &'a RandomnessSpacePublicParameters {
        &self.as_ref().randomness_space_public_parameters
    }

    fn commitment_space_public_parameters(&'a self) -> &'a CommitmentSpacePublicParameters {
        &self.as_ref().commitment_space_public_parameters
    }
}

impl<
        'a,
        MessageSpacePublicParameters: 'a,
        RandomnessSpacePublicParameters: 'a,
        CommitmentSpacePublicParameters: 'a,
        T: AsRef<
            GroupsPublicParameters<
                MessageSpacePublicParameters,
                RandomnessSpacePublicParameters,
                CommitmentSpacePublicParameters,
            >,
        >,
    >
    GroupsPublicParametersAccessors<
        'a,
        MessageSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
    > for T
{
}

// ── `CanonicalGroupsPublicParameters` ────────────────────────────────────────

#[derive(Serialize)]
pub struct CanonicalGroupsPublicParameters<
    MessageSpacePublicParameters: Transcribeable,
    RandomnessSpacePublicParameters: Transcribeable,
    CommitmentSpacePublicParameters: Transcribeable,
> {
    pub canonical_message_space_public_parameters:
        MessageSpacePublicParameters::CanonicalRepresentation,
    pub canonical_randomness_space_public_parameters:
        RandomnessSpacePublicParameters::CanonicalRepresentation,
    pub canonical_commitment_space_public_parameters:
        CommitmentSpacePublicParameters::CanonicalRepresentation,
}

impl<
        MessageSpacePublicParameters: Transcribeable,
        RandomnessSpacePublicParameters: Transcribeable,
        CommitmentSpacePublicParameters: Transcribeable,
    >
    From<
        GroupsPublicParameters<
            MessageSpacePublicParameters,
            RandomnessSpacePublicParameters,
            CommitmentSpacePublicParameters,
        >,
    >
    for CanonicalGroupsPublicParameters<
        MessageSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
    >
{
    fn from(
        value: GroupsPublicParameters<
            MessageSpacePublicParameters,
            RandomnessSpacePublicParameters,
            CommitmentSpacePublicParameters,
        >,
    ) -> Self {
        Self {
            canonical_message_space_public_parameters: value
                .message_space_public_parameters
                .into(),
            canonical_randomness_space_public_parameters: value
                .randomness_space_public_parameters
                .into(),
            canonical_commitment_space_public_parameters: value
                .commitment_space_public_parameters
                .into(),
        }
    }
}

// ── Convenience type aliases ──────────────────────────────────────────────────

pub type PublicParameters<const MESSAGE_SPACE_SCALAR_LIMBS: usize, C> =
    <C as HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>>::PublicParameters;

pub type MessageSpaceGroupElement<const MESSAGE_SPACE_SCALAR_LIMBS: usize, C> =
    <C as HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>>::MessageSpaceGroupElement;

pub type MessageSpacePublicParameters<const MESSAGE_SPACE_SCALAR_LIMBS: usize, C> =
    group::PublicParameters<
        <C as HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>>::MessageSpaceGroupElement,
    >;

pub type MessageSpaceValue<const MESSAGE_SPACE_SCALAR_LIMBS: usize, C> = group::Value<
    <C as HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>>::MessageSpaceGroupElement,
>;

pub type RandomnessSpaceGroupElement<const MESSAGE_SPACE_SCALAR_LIMBS: usize, C> =
    <C as HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>>::RandomnessSpaceGroupElement;

pub type RandomnessSpacePublicParameters<const MESSAGE_SPACE_SCALAR_LIMBS: usize, C> =
    group::PublicParameters<
        <C as HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>>::RandomnessSpaceGroupElement,
    >;

pub type RandomnessSpaceValue<const MESSAGE_SPACE_SCALAR_LIMBS: usize, C> = group::Value<
    <C as HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>>::RandomnessSpaceGroupElement,
>;

pub type CommitmentSpaceGroupElement<const MESSAGE_SPACE_SCALAR_LIMBS: usize, C> =
    <C as HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentSpaceGroupElement;

pub type CommitmentSpacePublicParameters<const MESSAGE_SPACE_SCALAR_LIMBS: usize, C> =
    group::PublicParameters<
        <C as HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentSpaceGroupElement,
    >;

pub type CommitmentSpaceValue<const MESSAGE_SPACE_SCALAR_LIMBS: usize, C> = group::Value<
    <C as HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentSpaceGroupElement,
>;
