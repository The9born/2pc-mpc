use std::fmt::Debug;
// Local re-implementation of the `commitment::pedersen` module.

use core::fmt::Debug;
use std::{array, marker::PhantomData, ops::Mul};

use serde::{Deserialize, Serialize};

use group::{
    helpers::{const_generic_array_serialization, FlatMapResults},
    self_product, BoundedGroupElement, HashToGroup, PrimeGroupElement, Samplable, Transcribeable,
};

use crate::{
    CanonicalGroupsPublicParameters, GroupsPublicParameters, GroupsPublicParametersAccessors,
    HomomorphicCommitmentScheme,
};

// ── `Pedersen` commitment scheme ──────────────────────────────────────────────

/// A Batched Pedersen Commitment:
/// $$\Com_\pp(m;\rho) = m_1\cdot G_1 + \ldots + m_n\cdot G_n + \rho \cdot H$$
#[derive(PartialEq, Clone, Debug, Eq)]
pub struct Pedersen<
    const BATCH_SIZE: usize,
    const SCALAR_LIMBS: usize,
    Scalar: group::GroupElement,
    GroupElement: group::GroupElement,
> {
    message_generators: [GroupElement; BATCH_SIZE],
    randomness_generator: GroupElement,
    _scalar_choice: PhantomData<Scalar>,
}

impl<const BATCH_SIZE: usize, const SCALAR_LIMBS: usize, Scalar, GroupElement>
    HomomorphicCommitmentScheme<SCALAR_LIMBS>
    for Pedersen<BATCH_SIZE, SCALAR_LIMBS, Scalar, GroupElement>
where
    Scalar: BoundedGroupElement<SCALAR_LIMBS>
        + Mul<GroupElement, Output = GroupElement>
        + for<'r> Mul<&'r GroupElement, Output = GroupElement>
        + Samplable
        + Copy,
    GroupElement: group::GroupElement,
{
    type MessageSpaceGroupElement = self_product::GroupElement<BATCH_SIZE, Scalar>;
    type RandomnessSpaceGroupElement = Scalar;
    type CommitmentSpaceGroupElement = GroupElement;
    type PublicParameters = PublicParameters<
        BATCH_SIZE,
        GroupElement::Value,
        Scalar::PublicParameters,
        GroupElement::PublicParameters,
    >;

    fn new(public_parameters: &Self::PublicParameters) -> crate::Result<Self> {
        if BATCH_SIZE == 0 {
            return Err(crate::Error::InvalidPublicParameters);
        }

        let message_generators = public_parameters
            .message_generators
            .map(|value| {
                GroupElement::new(
                    value,
                    public_parameters.commitment_space_public_parameters(),
                )
            })
            .flat_map_results()?;

        let randomness_generator = GroupElement::new(
            public_parameters.randomness_generator,
            public_parameters.commitment_space_public_parameters(),
        )?;

        if message_generators
            .iter()
            .any(|generator| bool::from(generator.is_neutral()))
            || bool::from(randomness_generator.is_neutral())
        {
            return Err(crate::Error::InvalidPublicParameters);
        }

        Ok(Self {
            message_generators,
            randomness_generator,
            _scalar_choice: PhantomData,
        })
    }

    fn commit(
        &self,
        message: &self_product::GroupElement<BATCH_SIZE, Scalar>,
        randomness: &Scalar,
    ) -> GroupElement {
        self.message_generators
            .iter()
            .zip::<&[Scalar; BATCH_SIZE]>(message.into())
            .fold(
                self.randomness_generator.neutral(),
                |acc, (generator, value)| acc + (*value * generator),
            )
            + (*randomness * self.randomness_generator)
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

/// The Public Parameters of a Pedersen Commitment.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct PublicParameters<
    const BATCH_SIZE: usize,
    GroupElementValue,
    ScalarPublicParameters,
    GroupPublicParameters,
> {
    pub groups_public_parameters: GroupsPublicParameters<
        self_product::PublicParameters<BATCH_SIZE, ScalarPublicParameters>,
        ScalarPublicParameters,
        GroupPublicParameters,
    >,
    #[serde(with = "const_generic_array_serialization")]
    pub message_generators: [GroupElementValue; BATCH_SIZE],
    pub randomness_generator: GroupElementValue,
}

impl<
        const BATCH_SIZE: usize,
        GroupElementValue: Clone,
        ScalarPublicParameters: Clone,
        GroupPublicParameters: Clone,
    > PublicParameters<BATCH_SIZE, GroupElementValue, ScalarPublicParameters, GroupPublicParameters>
{
    /// Derive Pedersen generators safely from the group's hash-to-group function.
    /// This is the preferred safe instantiation method.
    pub fn derive_default<const SCALAR_LIMBS: usize, GroupElement>() -> crate::Result<Self>
    where
        GroupElement::Scalar: group::GroupElement<PublicParameters = ScalarPublicParameters>,
        GroupElement: group::GroupElement<
                Value = GroupElementValue,
                PublicParameters = GroupPublicParameters,
            > + PrimeGroupElement<SCALAR_LIMBS>
            + HashToGroup,
        ScalarPublicParameters: Default,
        GroupPublicParameters: Default,
    {
        Self::derive::<SCALAR_LIMBS, GroupElement>(
            ScalarPublicParameters::default(),
            GroupPublicParameters::default(),
        )
    }

    /// Derive Pedersen generators safely from the group's hash-to-group function given explicit
    /// public parameters.
    pub fn derive<const SCALAR_LIMBS: usize, GroupElement>(
        scalar_public_parameters: group::PublicParameters<GroupElement::Scalar>,
        group_public_parameters: group::PublicParameters<GroupElement>,
    ) -> crate::Result<Self>
    where
        GroupElement::Scalar: group::GroupElement<PublicParameters = ScalarPublicParameters>,
        GroupElement: group::GroupElement<
                Value = GroupElementValue,
                PublicParameters = GroupPublicParameters,
            > + PrimeGroupElement<SCALAR_LIMBS>
            + HashToGroup,
    {
        let message_generators = array::from_fn(|i| {
            if i == 0 {
                GroupElement::generator_from_public_parameters(&group_public_parameters)
            } else {
                GroupElement::hash_to_group(
                    format!("commitment/pedersen: message generator #{i:?}").as_bytes(),
                )
            }
        })
        .flat_map_results()?;

        let message_generators = message_generators.map(|element| element.value());

        let randomness_generator =
            GroupElement::hash_to_group("commitment/pedersen: randomness generator".as_bytes())?
                .value();

        Ok(Self::new::<SCALAR_LIMBS, GroupElement::Scalar, GroupElement>(
            scalar_public_parameters,
            group_public_parameters,
            message_generators,
            randomness_generator,
        ))
    }

    /// Create Pedersen public parameters from explicit generators.
    /// Only use this when you have a specific reason not to use [`Self::derive`].
    pub fn new<const SCALAR_LIMBS: usize, Scalar, GroupElement>(
        scalar_public_parameters: group::PublicParameters<Scalar>,
        group_public_parameters: group::PublicParameters<GroupElement>,
        message_generators: [group::Value<GroupElement>; BATCH_SIZE],
        randomness_generator: group::Value<GroupElement>,
    ) -> Self
    where
        Scalar: group::GroupElement<PublicParameters = ScalarPublicParameters>
            + BoundedGroupElement<SCALAR_LIMBS>
            + Mul<GroupElement, Output = GroupElement>
            + for<'r> Mul<&'r GroupElement, Output = GroupElement>
            + Samplable
            + Copy,
        GroupElement: group::GroupElement<
            Value = GroupElementValue,
            PublicParameters = GroupPublicParameters,
        >,
    {
        Self {
            groups_public_parameters: GroupsPublicParameters {
                message_space_public_parameters: self_product::PublicParameters::new(
                    scalar_public_parameters.clone(),
                ),
                randomness_space_public_parameters: scalar_public_parameters,
                commitment_space_public_parameters: group_public_parameters,
            },
            message_generators,
            randomness_generator,
        }
    }

    pub fn with_altered_message_generators(
        &self,
        message_generators: [GroupElementValue; BATCH_SIZE],
    ) -> Self {
        Self {
            groups_public_parameters: self.groups_public_parameters.clone(),
            message_generators,
            randomness_generator: self.randomness_generator.clone(),
        }
    }

    pub fn with_altered_randomness_generator(
        &self,
        randomness_generator: GroupElementValue,
    ) -> Self {
        Self {
            groups_public_parameters: self.groups_public_parameters.clone(),
            message_generators: self.message_generators.clone(),
            randomness_generator,
        }
    }
}

impl<const BATCH_SIZE: usize, GroupElementValue, ScalarPublicParameters, GroupPublicParameters>
    AsRef<
        GroupsPublicParameters<
            self_product::PublicParameters<BATCH_SIZE, ScalarPublicParameters>,
            ScalarPublicParameters,
            GroupPublicParameters,
        >,
    >
    for PublicParameters<BATCH_SIZE, GroupElementValue, ScalarPublicParameters, GroupPublicParameters>
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        self_product::PublicParameters<BATCH_SIZE, ScalarPublicParameters>,
        ScalarPublicParameters,
        GroupPublicParameters,
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
        ScalarPublicParameters,
        GroupPublicParameters,
    >,
    #[serde(with = "const_generic_array_serialization")]
    message_generators: [GroupElementValue; BATCH_SIZE],
    randomness_generator: GroupElementValue,
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
            message_generators: value.message_generators,
            randomness_generator: value.randomness_generator,
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
