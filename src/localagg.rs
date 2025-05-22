use std::{collections::HashMap, time::Duration};

use group::PartyID;
use proof::aggregation::{
    CommitmentRoundParty, DecommitmentRoundParty, ProofAggregationRoundParty, ProofShareRoundParty,
};
use rand_core::OsRng;

pub fn aggregates<Output, P: CommitmentRoundParty<Output>>(
    commitment_round_parties: HashMap<PartyID, P>,
) -> (Duration, Duration, Duration, Duration, Duration, Output) {
    let (
        commitment_round_time,
        decommitment_round_time,
        proof_share_round_time,
        proof_aggregation_round_time,
        total_time,
        outputs,
    ) = aggregates_multiple(
        commitment_round_parties
            .into_iter()
            .map(|(party_id, party)| (party_id, vec![party]))
            .collect(),
    );

    (
        commitment_round_time,
        decommitment_round_time,
        proof_share_round_time,
        proof_aggregation_round_time,
        total_time,
        outputs.into_iter().next().unwrap(),
    )
}

/// Test aggregation over multiple claims in parallel.
pub fn aggregates_multiple<Output, P: CommitmentRoundParty<Output>>(
    commitment_round_parties: HashMap<PartyID, Vec<P>>,
) -> (
    Duration,
    Duration,
    Duration,
    Duration,
    Duration,
    Vec<Output>,
) {
    let (
        _,
        commitment_round_time,
        decommitment_round_time,
        proof_share_round_time,
        proof_aggregation_round_time,
        total_time,
        outputs,
    ) = aggregates_multiple_with_decommitments(commitment_round_parties);

    (
        commitment_round_time,
        decommitment_round_time,
        proof_share_round_time,
        proof_aggregation_round_time,
        total_time,
        outputs,
    )
}

/// Test aggregation over multiple claims in parallel, returning decommitments as well.
pub fn aggregates_multiple_with_decommitments<Output, P: CommitmentRoundParty<Output>>(
    commitment_round_parties: HashMap<PartyID, Vec<P>>,
) -> (
    HashMap<
        PartyID,
        Vec<<P::DecommitmentRoundParty as DecommitmentRoundParty<Output>>::Decommitment>,
    >,
    Duration,
    Duration,
    Duration,
    Duration,
    Duration,
    Vec<Output>,
) {
    // let measurement = WallTime;
    let mut commitment_round_time = Duration::default();
    let mut decommitment_round_time = Duration::default();
    let mut proof_share_round_time = Duration::default();

    let batch_size = commitment_round_parties.iter().next().unwrap().1.len();

    let commitments_and_decommitment_round_parties: HashMap<_, Vec<(_, _)>> =
        commitment_round_parties
            .into_iter()
            .map(|(party_id, parties)| {
                // let now = measurement.start();
                let res = parties
                    .into_iter()
                    .map(|party| {
                        party
                            .commit_statements_and_statement_mask(&mut OsRng)
                            .unwrap()
                    })
                    .collect();
                // commitment_round_time = measurement.end(now);

                (party_id, res)
            })
            .collect();

    let commitments: HashMap<_, Vec<_>> = commitments_and_decommitment_round_parties
        .iter()
        .map(|(party_id, v)| {
            (
                *party_id,
                v.iter().map(|(commitment, _)| commitment.clone()).collect(),
            )
        })
        .collect();

    let commitments: Vec<HashMap<_, _>> = (0..batch_size)
        .map(|i| {
            commitments
                .iter()
                .map(|(party_id, commitments)| (*party_id, commitments[i].clone()))
                .collect()
        })
        .collect();

    let decommitments_and_proof_share_round_parties: HashMap<_, Vec<(_, _)>> =
        commitments_and_decommitment_round_parties
            .into_iter()
            .map(|(party_id, v)| {
                // let now = measurement.start();
                let res = v
                    .into_iter()
                    .enumerate()
                    .map(|(i, (_, party))| {
                        party
                            .decommit_statements_and_statement_mask(
                                commitments[i].clone(),
                                &mut OsRng,
                            )
                            .unwrap()
                    })
                    .collect();
                // decommitment_round_time = measurement.end(now);

                (party_id, res)
            })
            .collect();

    let decommitments_vecs: HashMap<_, Vec<_>> = decommitments_and_proof_share_round_parties
        .iter()
        .map(|(party_id, v)| {
            (
                *party_id,
                v.iter()
                    .map(|(decommitment, _)| decommitment.clone())
                    .collect(),
            )
        })
        .collect();

    let decommitments: Vec<HashMap<_, _>> = (0..batch_size)
        .map(|i| {
            decommitments_vecs
                .iter()
                .map(|(party_id, decommitments)| (*party_id, decommitments[i].clone()))
                .collect()
        })
        .collect();

    let proof_shares_and_proof_aggregation_round_parties: HashMap<_, Vec<(_, _)>> =
        decommitments_and_proof_share_round_parties
            .into_iter()
            .map(|(party_id, v)| {
                // let now = measurement.start();
                let res = v
                    .into_iter()
                    .enumerate()
                    .map(|(i, (_, party))| {
                        party
                            .generate_proof_share(decommitments[i].clone(), &mut OsRng)
                            .unwrap()
                    })
                    .collect();
                // proof_share_round_time = measurement.end(now);

                (party_id, res)
            })
            .collect();

    let proof_shares: HashMap<_, Vec<_>> = proof_shares_and_proof_aggregation_round_parties
        .iter()
        .map(|(party_id, v)| {
            (
                *party_id,
                v.iter()
                    .map(|(proof_share, _)| proof_share.clone())
                    .collect(),
            )
        })
        .collect();

    let proof_shares: Vec<HashMap<_, _>> = (0..batch_size)
        .map(|i| {
            proof_shares
                .iter()
                .map(|(party_id, proof_shares)| (*party_id, proof_shares[i].clone()))
                .collect()
        })
        .collect();

    let (_, proof_aggregation_round_parties) = proof_shares_and_proof_aggregation_round_parties
        .into_iter()
        .next()
        .unwrap();

    let (_, proof_aggregation_round_parties): (Vec<_>, Vec<_>) =
        proof_aggregation_round_parties.into_iter().unzip();

    // let now = measurement.start();
    let outputs = proof_aggregation_round_parties
        .into_iter()
        .enumerate()
        .map(|(i, proof_aggregation_round_party)| {
            proof_aggregation_round_party
                .aggregate_proof_shares(proof_shares[i].clone(), &mut OsRng)
                .unwrap()
        })
        .collect();

    // let proof_aggregation_round_time = measurement.end(now);
    // let total_time = measurement.add(&commitment_round_time, &decommitment_round_time);
    // let total_time = measurement.add(&total_time, &proof_share_round_time);
    // let total_time = measurement.add(&total_time, &proof_aggregation_round_time);
    let total_time = Duration::default();
    let proof_aggregation_round_time = Duration::default();

    (
        decommitments_vecs,
        commitment_round_time,
        decommitment_round_time,
        proof_share_round_time,
        proof_aggregation_round_time,
        total_time,
        outputs,
    )
}

pub fn aggregates_with_decommitments<Output, P: CommitmentRoundParty<Output>>(
    commitment_round_parties: HashMap<PartyID, P>,
) -> (
    HashMap<
        PartyID,
        Vec<<P::DecommitmentRoundParty as DecommitmentRoundParty<Output>>::Decommitment>,
    >,
    Duration,
    Duration,
    Duration,
    Duration,
    Duration,
    Output,
) {
    let (
        decommitments,
        commitment_round_time,
        decommitment_round_time,
        proof_share_round_time,
        proof_aggregation_round_time,
        total_time,
        outputs,
    ) = aggregates_multiple_with_decommitments(
        commitment_round_parties
            .into_iter()
            .map(|(party_id, party)| (party_id, vec![party]))
            .collect(),
    );

    (
        decommitments,
        commitment_round_time,
        decommitment_round_time,
        proof_share_round_time,
        proof_aggregation_round_time,
        total_time,
        outputs.into_iter().next().unwrap(),
    )
}
