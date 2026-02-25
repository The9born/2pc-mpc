// Local re-implementation of the `commitment::multipedersen` module.

use std::ops::Mul;

use serde::{Deserialize, Serialize};

use group::{self_product, BoundedGroupElement, Samplable, Transcribeable};

use crate::{
    pedersen, CanonicalGroupsPublicParameters, GroupsPublicParameters, HomomorphicCommitmentScheme,
    Pedersen,
};

// ── `MultiPedersen` ───────────────────────────────────────────────────────────

/// A Batched Pedersen Commitment:
/// $$\Com_\pp(m;\rho) = (m_1\cdot G + \rho_1 \cdot H, \ldots, m_n\cdot G + \rho_n \cdot H)$$
#[derive(PartialEq, Clone, Debug, Eq)]
pub struct MultiPedersen<
    const BATCH_SIZE: usize,
    const SCALAR_LIMBS: usize,
    Scalar: group::GroupElement,
    GroupElement: group::GroupElement,
>(Pedersen<1, SCALAR_LIMBS, Scalar, GroupElement>);

impl<const BATCH_SIZE: usize, const SCALAR_LIMBS: usize, Scalar, GroupElement>
    HomomorphicCommitmentScheme<SCALAR_LIMBS>
    for MultiPedersen<BATCH_SIZE, SCALAR_LIMBS, Scalar, GroupElement>
where
    Scalar: BoundedGroupElement<SCALAR_LIMBS>
        + Mul<GroupElement, Output = GroupElement>
        + for<'r> Mul<&'r GroupElement, Output = GroupElement>
        + Samplable
        + Copy,
    GroupElement: group::GroupElement,
{
    type MessageSpaceGroupElement = self_product::GroupElement<BATCH_SIZE, Scalar>;
    type RandomnessSpaceGroupElement = self_product::GroupElement<BATCH_SIZE, Scalar>;
    type CommitmentSpaceGroupElement = self_product::GroupElement<BATCH_SIZE, GroupElement>;
    type PublicParameters = PublicParameters<
        BATCH_SIZE,
        GroupElement::Value,
        Scalar::PublicParameters,
        GroupElement::PublicParameters,
    >;

    fn new(public_parameters: &Self::PublicParameters) -> crate::Result<Self> {
        Pedersen::new(&public_parameters.pedersen_public_parameters).map(Self)
    }

    fn commit(
        &self,
        message: &Self::MessageSpaceGroupElement,
        randomness: &Self::RandomnessSpaceGroupElement,
    ) -> Self::CommitmentSpaceGroupElement {
        let messages: [_; BATCH_SIZE] = (*message).into();
        let randomnesses: [_; BATCH_SIZE] = (*randomness).into();

        let commitments: [_; BATCH_SIZE] = messages
            .into_iter()
            .zip(randomnesses)
            .map(|(message, randomness)| self.0.commit(&[message].into(), &randomness))
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap();

        commitments.into()
    }
}

// ── Type aliases ──────────────────────────────────────────────────────────────

pub type MessageSpaceGroupElement<const BATCH_SIZE: usize, Scalar> =
    self_product::GroupElement<BATCH_SIZE, Scalar>;
pub type MessageSpacePublicParameters<const BATCH_SIZE: usize, Scalar> =
    group::PublicParameters<MessageSpaceGroupElement<BATCH_SIZE, Scalar>>;
pub type RandomnessSpaceGroupElement<Scalar> = Scalar;
pub type RandomnessSpacePublicParameters<Scalar> =
    group::PublicParameters<RandomnessSpaceGroupElement<Scalar>>;
pub type CommitmentSpaceGroupElement<GroupElement> = GroupElement;
pub type CommitmentSpacePublicParameters<GroupElement> =
    group::PublicParameters<CommitmentSpaceGroupElement<GroupElement>>;

// ── `PublicParameters` ────────────────────────────────────────────────────────

/// The Public Parameters of a Multi-Pedersen Commitment.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct PublicParameters<
    const BATCH_SIZE: usize,
    GroupElementValue,
    ScalarPublicParameters,
    GroupPublicParameters,
> {
    pub groups_public_parameters: GroupsPublicParameters<
        self_product::PublicParameters<BATCH_SIZE, ScalarPublicParameters>,
        self_product::PublicParameters<BATCH_SIZE, ScalarPublicParameters>,
        self_product::PublicParameters<BATCH_SIZE, GroupPublicParameters>,
    >,
    pub pedersen_public_parameters: pedersen::PublicParameters<
        1,
        GroupElementValue,
        ScalarPublicParameters,
        GroupPublicParameters,
    >,
}

impl<
        const BATCH_SIZE: usize,
        GroupElementValue: Copy,
        ScalarPublicParameters: Clone,
        GroupPublicParameters: Clone,
    >
    From<
        pedersen::PublicParameters<
            1,
            GroupElementValue,
            ScalarPublicParameters,
            GroupPublicParameters,
        >,
    >
    for PublicParameters<BATCH_SIZE, GroupElementValue, ScalarPublicParameters, GroupPublicParameters>
{
    fn from(
        pedersen_public_parameters: pedersen::PublicParameters<
            1,
            GroupElementValue,
            ScalarPublicParameters,
            GroupPublicParameters,
        >,
    ) -> Self {
        Self {
            groups_public_parameters: GroupsPublicParameters {
                message_space_public_parameters: self_product::PublicParameters::new(
                    pedersen_public_parameters
                        .groups_public_parameters
                        .randomness_space_public_parameters
                        .clone(),
                ),
                randomness_space_public_parameters: self_product::PublicParameters::new(
                    pedersen_public_parameters
                        .groups_public_parameters
                        .randomness_space_public_parameters
                        .clone(),
                ),
                commitment_space_public_parameters: self_product::PublicParameters::new(
                    pedersen_public_parameters
                        .groups_public_parameters
                        .commitment_space_public_parameters
                        .clone(),
                ),
            },
            pedersen_public_parameters,
        }
    }
}

impl<const BATCH_SIZE: usize, GroupElementValue, ScalarPublicParameters, GroupPublicParameters>
    AsRef<
        GroupsPublicParameters<
            self_product::PublicParameters<BATCH_SIZE, ScalarPublicParameters>,
            self_product::PublicParameters<BATCH_SIZE, ScalarPublicParameters>,
            self_product::PublicParameters<BATCH_SIZE, GroupPublicParameters>,
        >,
    >
    for PublicParameters<BATCH_SIZE, GroupElementValue, ScalarPublicParameters, GroupPublicParameters>
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        self_product::PublicParameters<BATCH_SIZE, ScalarPublicParameters>,
        self_product::PublicParameters<BATCH_SIZE, ScalarPublicParameters>,
        self_product::PublicParameters<BATCH_SIZE, GroupPublicParameters>,
    > {
        &self.groups_public_parameters
    }
}

// ── `CanonicalPublicParameters` ───────────────────────────────────────────────

#[derive(Serialize)]
pub struct CanonicalPublicParameters<
    const BATCH_SIZE: usize,
    GroupElementValue: Serialize,
    ScalarPublicParameters: Transcribeable,
    GroupPublicParameters: Transcribeable,
> {
    canonical_groups_public_parameters: CanonicalGroupsPublicParameters<
        self_product::PublicParameters<BATCH_SIZE, ScalarPublicParameters>,
        self_product::PublicParameters<BATCH_SIZE, ScalarPublicParameters>,
        self_product::PublicParameters<BATCH_SIZE, GroupPublicParameters>,
    >,
    canonical_pedersen_public_parameters: pedersen::CanonicalPublicParameters<
        1,
        GroupElementValue,
        ScalarPublicParameters,
        GroupPublicParameters,
    >,
}

impl<
        const BATCH_SIZE: usize,
        GroupElementValue: Serialize,
        ScalarPublicParameters: Transcribeable,
        GroupPublicParameters: Transcribeable,
    >
    From<PublicParameters<BATCH_SIZE, GroupElementValue, ScalarPublicParameters, GroupPublicParameters>>
    for CanonicalPublicParameters<
        BATCH_SIZE,
        GroupElementValue,
        ScalarPublicParameters,
        GroupPublicParameters,
    >
{
    fn from(
        value: PublicParameters<
            BATCH_SIZE,
            GroupElementValue,
            ScalarPublicParameters,
            GroupPublicParameters,
        >,
    ) -> Self {
        Self {
            canonical_groups_public_parameters: value.groups_public_parameters.into(),
            canonical_pedersen_public_parameters: value.pedersen_public_parameters.into(),
        }
    }
}

impl<
        const BATCH_SIZE: usize,
        GroupElementValue: Serialize,
        ScalarPublicParameters: Transcribeable + Serialize,
        GroupPublicParameters: Transcribeable + Serialize,
    > Transcribeable
    for PublicParameters<BATCH_SIZE, GroupElementValue, ScalarPublicParameters, GroupPublicParameters>
{
    type CanonicalRepresentation = CanonicalPublicParameters<
        BATCH_SIZE,
        GroupElementValue,
        ScalarPublicParameters,
        GroupPublicParameters,
    >;
}
