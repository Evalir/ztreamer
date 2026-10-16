//! Compact index record projection, shielded-pool filtering, and protobuf response construction.

use std::collections::HashSet;

use tonic::Status;
use zakura_chain::{serialization::ZcashDeserialize as _, transaction};
use ztreamer_indexer::{
    Digest,
    parser::{CompactShieldedAction, CompactTransaction, parse_transaction},
};
use ztreamer_protocol::proto;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PoolSelection {
    pub(crate) transparent: bool,
    sapling: bool,
    orchard: bool,
    ironwood: bool,
}

impl PoolSelection {
    pub(crate) fn is_all(self) -> bool {
        !self.transparent && self.sapling && self.orchard && self.ironwood
    }

    pub(crate) fn from_request(pool_types: &[i32]) -> Result<Self, Status> {
        Self::from_mempool_request(pool_types)
    }

    /// Empty means every shielded pool, for compatibility with legacy clients.
    pub(crate) fn from_mempool_request(pool_types: &[i32]) -> Result<Self, Status> {
        if pool_types.is_empty() {
            return Ok(Self {
                transparent: false,
                sapling: true,
                orchard: true,
                ironwood: true,
            });
        }

        let mut selection = Self {
            transparent: false,
            sapling: false,
            orchard: false,
            ironwood: false,
        };
        for &pool_type in pool_types {
            match proto::PoolType::try_from(pool_type) {
                Ok(proto::PoolType::Sapling) => selection.sapling = true,
                Ok(proto::PoolType::Orchard) => selection.orchard = true,
                Ok(proto::PoolType::Ironwood) => selection.ironwood = true,
                Ok(proto::PoolType::Transparent) => selection.transparent = true,
                Ok(proto::PoolType::Invalid) | Err(_) => {
                    return Err(Status::invalid_argument(format!(
                        "invalid pool type {pool_type}"
                    )));
                }
            }
        }
        Ok(selection)
    }
}

/// Project in place: discarded pools need no second record/object graph.
pub(crate) fn project_block(
    mut block: proto::CompactBlock,
    pools: PoolSelection,
    nullifiers: bool,
) -> proto::CompactBlock {
    for tx in &mut block.vtx {
        if !pools.sapling {
            tx.spends.clear();
        }
        if !pools.sapling || nullifiers {
            tx.outputs.clear();
        }
        if !pools.orchard {
            tx.actions.clear();
        }
        if !pools.ironwood {
            tx.ironwood_actions.clear();
        }
        if nullifiers {
            for action in tx.actions.iter_mut().chain(&mut tx.ironwood_actions) {
                action.cmx.clear();
                action.ephemeral_key.clear();
                action.ciphertext.clear();
            }
        }
    }
    if nullifiers {
        block.chain_metadata = Some(proto::ChainMetadata::default());
    } else {
        block.vtx.retain(|tx| {
            !tx.spends.is_empty()
                || !tx.outputs.is_empty()
                || !tx.actions.is_empty()
                || !tx.ironwood_actions.is_empty()
        });
    }
    block
}

/// [`project_block`] for an encoded block, without decoding it: the result is the same
/// bytes as decoding, projecting and re-encoding. Returns `None` for anything other than
/// the canonical layout the index writes, so callers can fall back to decoding.
pub(crate) fn project_encoded(
    block: &[u8],
    pools: PoolSelection,
    nullifiers: bool,
) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(block.len());
    let mut tx = Vec::new();
    let mut previous = 0;
    for field in Fields(block) {
        let field = field?;
        // Prost writes fields in tag order, with repeated transactions together.
        if field.number < previous || (field.number == previous && field.number != 7) {
            return None;
        }
        previous = field.number;
        if field.value.is_some() != matches!(field.number, 3 | 4 | 6 | 7 | 8) {
            return None;
        }
        match field.number {
            2..=6 => out.extend_from_slice(field.raw),
            7 => {
                tx.clear();
                if project_tx(
                    field.value.expect("checked above"),
                    pools,
                    nullifiers,
                    &mut tx,
                )? {
                    put_message(&mut out, 7, &tx);
                }
            }
            8 if nullifiers => {}
            8 => out.extend_from_slice(field.raw),
            _ => return None,
        }
    }
    if nullifiers {
        put_message(&mut out, 8, &[]);
    }
    Some(out)
}

/// Writes the projected transaction and reports whether [`project_block`] would keep it.
fn project_tx(
    tx: &[u8],
    pools: PoolSelection,
    nullifiers: bool,
    out: &mut Vec<u8>,
) -> Option<bool> {
    // CompactTx tag order (1-6, then 9); vin/vout (7, 8) never occur in the compact index.
    const ORDER: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 0, 0, 7];
    let mut previous = 0;
    let mut shielded = false;
    for field in Fields(tx) {
        let field = field?;
        let rank = *ORDER
            .get(field.number as usize)
            .filter(|rank| **rank != 0)?;
        if rank < previous || (rank == previous && rank < 4) {
            return None;
        }
        previous = rank;
        if field.value.is_some() == matches!(field.number, 1 | 3) {
            return None;
        }
        let keep = match field.number {
            1..=3 => {
                out.extend_from_slice(field.raw);
                continue;
            }
            4 => pools.sapling,
            5 => pools.sapling && !nullifiers,
            6 => pools.orchard,
            9 => pools.ironwood,
            _ => unreachable!("ranked above"),
        };
        if !keep {
            continue;
        }
        shielded = true;
        if nullifiers && matches!(field.number, 6 | 9) {
            let mut nullifier: &[u8] = &[];
            for action_field in Fields(field.value?) {
                let action_field = action_field?;
                if action_field.value.is_none() || !(1..=4).contains(&action_field.number) {
                    return None;
                }
                if action_field.number == 1 {
                    nullifier = action_field.raw;
                }
            }
            put_message(out, field.number, nullifier);
        } else {
            out.extend_from_slice(field.raw);
        }
    }
    Some(shielded || nullifiers)
}

fn put_message(out: &mut Vec<u8>, number: u32, message: &[u8]) {
    prost::encoding::encode_key(number, prost::encoding::WireType::LengthDelimited, out);
    prost::encoding::encode_varint(message.len() as u64, out);
    out.extend_from_slice(message);
}

/// One varint or length-delimited protobuf field.
struct Field<'a> {
    number: u32,
    /// The field including its key, for copying verbatim.
    raw: &'a [u8],
    /// A length-delimited field's contents.
    value: Option<&'a [u8]>,
}

/// Iterates fields, yielding `None` on malformed input or other wire types.
struct Fields<'a>(&'a [u8]);

impl<'a> Iterator for Fields<'a> {
    type Item = Option<Field<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            return None;
        }
        let start = self.0;
        let field = (|| {
            let (number, wire_type) = prost::encoding::decode_key(&mut self.0).ok()?;
            let value = match wire_type {
                prost::encoding::WireType::Varint => {
                    prost::encoding::decode_varint(&mut self.0).ok()?;
                    None
                }
                prost::encoding::WireType::LengthDelimited => {
                    let len = usize::try_from(prost::encoding::decode_varint(&mut self.0).ok()?)
                        .ok()
                        .filter(|len| *len <= self.0.len())?;
                    let (value, rest) = self.0.split_at(len);
                    self.0 = rest;
                    Some(value)
                }
                _ => return None,
            };
            Some(Field {
                number,
                raw: &start[..start.len() - self.0.len()],
                value,
            })
        })();
        if field.is_none() {
            // Stop after malformed input.
            self.0 = &[];
        }
        Some(field)
    }
}

pub(crate) fn add_transparent_txs(
    block: &mut proto::CompactBlock,
    transactions: &[std::sync::Arc<transaction::Transaction>],
) {
    for (index, tx) in transactions.iter().enumerate() {
        let vin: Vec<_> = tx
            .spent_outpoints()
            .map(|outpoint| proto::CompactTxIn {
                prevout_txid: outpoint.hash.0.to_vec(),
                prevout_index: outpoint.index,
            })
            .collect();
        let vout: Vec<_> = tx
            .outputs()
            .iter()
            .map(|output| proto::TxOut {
                value: output.value.into(),
                script_pub_key: output.lock_script.as_raw_bytes().to_vec(),
            })
            .collect();
        if vin.is_empty() && vout.is_empty() {
            continue;
        }
        let index = index as u64;
        let position = match block.vtx.binary_search_by_key(&index, |tx| tx.index) {
            Ok(position) => position,
            Err(position) => {
                block.vtx.insert(
                    position,
                    proto::CompactTx {
                        index,
                        txid: tx.hash().0.to_vec(),
                        ..Default::default()
                    },
                );
                position
            }
        };
        block.vtx[position].vin = vin;
        block.vtx[position].vout = vout;
    }
}

pub(crate) fn compact_mempool_txs(
    transactions: &[(Vec<u8>, transaction::Hash)],
    pools: PoolSelection,
    exclude_txid_suffixes: &[Vec<u8>],
) -> Result<Vec<proto::CompactTx>, Status> {
    let excluded = excluded_txids(
        transactions.iter().map(|(_, txid)| txid.0),
        exclude_txid_suffixes,
    );
    let mut compact = Vec::with_capacity(transactions.len().saturating_sub(excluded.len()));
    for (bytes, txid) in transactions {
        if excluded.contains(&txid.0) {
            continue;
        }
        let transaction = parse_transaction(bytes, *txid, 0).map_err(|error| {
            Status::internal(format!("mempool transaction {txid} is unparsable: {error}"))
        })?;
        let mut compact_tx = convert_transaction(&transaction, pools, false);
        if pools.transparent {
            let transaction = transaction::Transaction::zcash_deserialize(bytes.as_slice())
                .map_err(|error| Status::internal(error.to_string()))?;
            let vin: Vec<_> = transaction
                .spent_outpoints()
                .map(|outpoint| proto::CompactTxIn {
                    prevout_txid: outpoint.hash.0.to_vec(),
                    prevout_index: outpoint.index,
                })
                .collect();
            let vout: Vec<_> = transaction
                .outputs()
                .iter()
                .map(|output| proto::TxOut {
                    value: output.value.into(),
                    script_pub_key: output.lock_script.as_raw_bytes().to_vec(),
                })
                .collect();
            if !vin.is_empty() || !vout.is_empty() {
                let compact_tx = compact_tx.get_or_insert_with(|| proto::CompactTx {
                    txid: txid.0.to_vec(),
                    ..Default::default()
                });
                compact_tx.vin = vin;
                compact_tx.vout = vout;
            }
        }
        if let Some(transaction) = compact_tx {
            compact.push(transaction);
        }
    }
    Ok(compact)
}

pub(crate) fn excluded_txids(
    txids: impl Iterator<Item = Digest>,
    suffixes: &[Vec<u8>],
) -> HashSet<Digest> {
    let mut excluded = HashSet::new();
    if suffixes.is_empty() {
        return excluded;
    }
    // Reversing turns suffix matches into contiguous prefix matches in sorted order.
    let mut reversed: Vec<_> = txids
        .map(|mut txid| {
            txid.reverse();
            txid
        })
        .collect();
    reversed.sort_unstable();
    for suffix in suffixes.iter().filter(|suffix| suffix.len() <= 32) {
        let prefix: Vec<_> = suffix.iter().rev().copied().collect();
        let start = reversed.partition_point(|txid| txid.as_slice() < prefix.as_slice());
        if let Some(txid) = reversed.get(start).filter(|txid| txid.starts_with(&prefix))
            && !reversed
                .get(start + 1)
                .is_some_and(|next| next.starts_with(&prefix))
        {
            let mut txid = *txid;
            txid.reverse();
            excluded.insert(txid);
        }
    }
    excluded
}

fn convert_transaction(
    transaction: &CompactTransaction,
    pools: PoolSelection,
    nullifiers_only: bool,
) -> Option<proto::CompactTx> {
    let spends = if pools.sapling {
        transaction
            .sapling_spends
            .iter()
            .map(|nullifier| proto::CompactSaplingSpend {
                nf: nullifier.to_vec(),
            })
            .collect()
    } else {
        Vec::new()
    };
    let outputs = if pools.sapling && !nullifiers_only {
        transaction
            .sapling_outputs
            .iter()
            .map(|output| proto::CompactSaplingOutput {
                cmu: output.cmu.to_vec(),
                ephemeral_key: output.ephemeral_key.to_vec(),
                ciphertext: output.ciphertext.to_vec(),
            })
            .collect()
    } else {
        Vec::new()
    };
    let actions = if pools.orchard {
        convert_actions(&transaction.orchard_actions, nullifiers_only)
    } else {
        Vec::new()
    };
    let ironwood_actions = if pools.ironwood {
        convert_actions(&transaction.ironwood_actions, nullifiers_only)
    } else {
        Vec::new()
    };

    (!spends.is_empty()
        || !outputs.is_empty()
        || !actions.is_empty()
        || !ironwood_actions.is_empty()
        || nullifiers_only)
        .then(|| proto::CompactTx {
            index: transaction.index,
            txid: transaction.txid.to_vec(),
            fee: 0,
            spends,
            outputs,
            actions,
            ironwood_actions,
            vin: Vec::new(),
            vout: Vec::new(),
        })
}

fn convert_actions(
    actions: &[CompactShieldedAction],
    nullifiers_only: bool,
) -> Vec<proto::CompactOrchardAction> {
    actions
        .iter()
        .map(|action| proto::CompactOrchardAction {
            nullifier: action.nullifier.to_vec(),
            cmx: if nullifiers_only {
                Vec::new()
            } else {
                action.commitment.to_vec()
            },
            ephemeral_key: if nullifiers_only {
                Vec::new()
            } else {
                action.ephemeral_key.to_vec()
            },
            ciphertext: if nullifiers_only {
                Vec::new()
            } else {
                action.ciphertext.to_vec()
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zakura_chain::{
        block::Block, serialization::ZcashSerialize as _, transaction::Transaction,
    };
    use zakura_test::vectors::{BLOCK_MAINNET_949496_BYTES, BLOCK_TESTNET_1842421_BYTES};
    use ztreamer_indexer::{
        codec::{CompactBlockRecord, TreeSizes},
        parser::{
            CompactSaplingOutput, CompactShieldedAction, CompactTransaction, RawIndexBlock,
            parse_block,
        },
    };

    #[test]
    fn encoded_projection_is_byte_identical_to_decoding() {
        use prost::Message as _;

        let mut records: Vec<CompactBlockRecord> =
            [&*BLOCK_MAINNET_949496_BYTES, &*BLOCK_TESTNET_1842421_BYTES]
                .into_iter()
                .map(|bytes| {
                    let block = Block::zcash_deserialize(bytes.as_slice()).unwrap();
                    let parsed = parse_block(&RawIndexBlock {
                        height: block.coinbase_height().unwrap(),
                        hash: block.hash(),
                        bytes: bytes.to_vec(),
                        txids: block.transactions.iter().map(|tx| tx.hash()).collect(),
                    })
                    .unwrap();
                    CompactBlockRecord {
                        height: parsed.height,
                        hash: parsed.hash,
                        previous_hash: parsed.previous_hash,
                        time: parsed.time,
                        transactions: parsed.transactions,
                        end_tree_sizes: TreeSizes {
                            sapling: 5,
                            orchard: 0,
                            ironwood: 300,
                        },
                    }
                })
                .collect();
        let shielded = |index: u64, spends, outputs, orchard, ironwood| CompactTransaction {
            index,
            txid: [index as u8; 32],
            sapling_spends: vec![[1; 32]; spends],
            sapling_outputs: vec![
                CompactSaplingOutput {
                    cmu: [2; 32],
                    ephemeral_key: [3; 32],
                    ciphertext: [4; 52],
                };
                outputs
            ],
            orchard_actions: (0..orchard).map(|n| action(n as u8)).collect(),
            ironwood_actions: (0..ironwood).map(|n| action(!n as u8)).collect(),
        };
        records.push(CompactBlockRecord {
            height: 0,
            hash: [5; 32],
            previous_hash: [6; 32],
            time: 0,
            transactions: vec![
                shielded(0, 1, 0, 0, 0),
                shielded(1, 0, 2, 0, 0),
                shielded(2, 0, 0, 3, 0),
                shielded(3, 0, 0, 0, 4),
                shielded(300, 2, 2, 2, 2),
            ],
            end_tree_sizes: TreeSizes::default(),
        });

        let pool_sets: [&[proto::PoolType]; 8] = [
            &[],
            &[proto::PoolType::Sapling],
            &[proto::PoolType::Orchard],
            &[proto::PoolType::Ironwood],
            &[proto::PoolType::Sapling, proto::PoolType::Orchard],
            &[proto::PoolType::Orchard, proto::PoolType::Ironwood],
            &[proto::PoolType::Sapling, proto::PoolType::Ironwood],
            &[
                proto::PoolType::Ironwood,
                proto::PoolType::Sapling,
                proto::PoolType::Orchard,
            ],
        ];
        for record in &records {
            let encoded = record.to_proto().encode_to_vec();
            for pools in pool_sets {
                let pools = pools.iter().map(|pool| *pool as i32).collect::<Vec<_>>();
                let pools = PoolSelection::from_request(&pools).unwrap();
                for nullifiers in [false, true] {
                    let expected = project_block(
                        proto::CompactBlock::decode(encoded.as_slice()).unwrap(),
                        pools,
                        nullifiers,
                    )
                    .encode_to_vec();
                    assert_eq!(
                        project_encoded(&encoded, pools, nullifiers),
                        Some(expected),
                        "{pools:?} nullifiers={nullifiers}"
                    );
                }
            }
        }
    }

    /// Deterministic SplitMix64, so failures reproduce.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        fn below(&mut self, bound: u64) -> u64 {
            self.next() % bound
        }

        fn scalar(&mut self) -> u64 {
            match self.below(3) {
                0 => 0,
                1 => self.below(300),
                _ => self.next() >> self.below(64),
            }
        }

        /// Any length, including empty, so nothing depends on the index's fixed widths.
        fn bytes(&mut self) -> Vec<u8> {
            let len = match self.below(4) {
                0 => 0,
                1 => 32,
                _ => self.below(200),
            };
            (0..len).map(|_| self.next() as u8).collect()
        }

        fn count(&mut self) -> usize {
            self.below(4) as usize
        }
    }

    #[test]
    fn encoded_projection_matches_decoding_on_random_blocks() {
        use prost::Message as _;

        let mut rng = Rng(20_261_016);
        let pool_types = [
            proto::PoolType::Sapling,
            proto::PoolType::Orchard,
            proto::PoolType::Ironwood,
        ];
        for _ in 0..3_000 {
            let action = |rng: &mut Rng| proto::CompactOrchardAction {
                nullifier: rng.bytes(),
                cmx: rng.bytes(),
                ephemeral_key: rng.bytes(),
                ciphertext: rng.bytes(),
            };
            let vtx = (0..rng.below(5))
                .map(|_| proto::CompactTx {
                    index: rng.scalar(),
                    txid: rng.bytes(),
                    fee: rng.scalar() as u32,
                    spends: (0..rng.count())
                        .map(|_| proto::CompactSaplingSpend { nf: rng.bytes() })
                        .collect(),
                    outputs: (0..rng.count())
                        .map(|_| proto::CompactSaplingOutput {
                            cmu: rng.bytes(),
                            ephemeral_key: rng.bytes(),
                            ciphertext: rng.bytes(),
                        })
                        .collect(),
                    actions: (0..rng.count()).map(|_| action(&mut rng)).collect(),
                    ironwood_actions: (0..rng.count()).map(|_| action(&mut rng)).collect(),
                    // The compact index never stores transparent data.
                    vin: Vec::new(),
                    vout: Vec::new(),
                })
                .collect();
            let block = proto::CompactBlock {
                height: rng.scalar(),
                hash: rng.bytes(),
                prev_hash: rng.bytes(),
                time: rng.scalar() as u32,
                header: if rng.below(4) == 0 {
                    rng.bytes()
                } else {
                    Vec::new()
                },
                vtx,
                chain_metadata: match rng.below(3) {
                    0 => None,
                    1 => Some(proto::ChainMetadata::default()),
                    _ => Some(proto::ChainMetadata {
                        sapling_commitment_tree_size: rng.scalar() as u32,
                        orchard_commitment_tree_size: rng.scalar() as u32,
                        ironwood_commitment_tree_size: rng.scalar() as u32,
                    }),
                },
            };
            let encoded = block.encode_to_vec();
            for mask in 0..8u8 {
                let pools = pool_types
                    .iter()
                    .enumerate()
                    .filter(|(bit, _)| mask & (1 << bit) != 0)
                    .map(|(_, pool)| *pool as i32)
                    .collect::<Vec<_>>();
                let pools = PoolSelection::from_request(&pools).unwrap();
                for nullifiers in [false, true] {
                    let expected = project_block(block.clone(), pools, nullifiers).encode_to_vec();
                    assert_eq!(
                        project_encoded(&encoded, pools, nullifiers),
                        Some(expected),
                        "{block:?} {pools:?} nullifiers={nullifiers}"
                    );
                }
            }
        }
    }

    #[test]
    fn encoded_projection_declines_non_canonical_input() {
        use prost::Message as _;

        let pools = PoolSelection::from_request(&[]).unwrap();
        let block = proto::CompactBlock {
            height: 1,
            hash: vec![1; 32],
            vtx: vec![proto::CompactTx {
                index: 1,
                txid: vec![2; 32],
                actions: vec![proto::CompactOrchardAction {
                    nullifier: vec![3; 32],
                    ..Default::default()
                }],
                ..Default::default()
            }],
            chain_metadata: Some(proto::ChainMetadata::default()),
            ..Default::default()
        };
        let encoded = block.encode_to_vec();
        assert!(project_encoded(&encoded, pools, true).is_some());

        let with_vin = proto::CompactBlock {
            vtx: vec![proto::CompactTx {
                vin: vec![proto::CompactTxIn::default()],
                ..block.vtx[0].clone()
            }],
            ..block.clone()
        };
        // Height (field 2, two bytes) moved after chain metadata.
        let reordered = [&encoded[2..], &encoded[..2]].concat();
        let mut unknown = encoded.clone();
        unknown.extend_from_slice(&[0x48, 1]);
        let mut wrong_type = encoded.clone();
        wrong_type[0] = 0x12;
        for input in [
            with_vin.encode_to_vec(),
            reordered,
            unknown,
            wrong_type,
            encoded[..encoded.len() - 1].to_vec(),
        ] {
            for nullifiers in [false, true] {
                assert_eq!(project_encoded(&input, pools, nullifiers), None);
            }
        }
    }

    #[test]
    fn validates_pools_and_projects_full_and_nullifier_blocks() {
        let record = CompactBlockRecord {
            height: 7,
            hash: [1; 32],
            previous_hash: [2; 32],
            time: 3,
            transactions: vec![CompactTransaction {
                index: 5,
                txid: [6; 32],
                sapling_spends: vec![[7; 32]],
                sapling_outputs: vec![CompactSaplingOutput {
                    cmu: [8; 32],
                    ephemeral_key: [9; 32],
                    ciphertext: [10; 52],
                }],
                orchard_actions: vec![action(11)],
                ironwood_actions: vec![action(12)],
            }],
            end_tree_sizes: TreeSizes {
                sapling: 13,
                orchard: 14,
                ironwood: 15,
            },
        };

        let orchard = project_block(
            record.to_proto(),
            PoolSelection::from_request(&[proto::PoolType::Orchard as i32]).unwrap(),
            false,
        );
        assert!(orchard.header.is_empty());
        assert!(orchard.vtx[0].spends.is_empty());
        assert_eq!(orchard.vtx[0].actions[0].cmx, vec![11; 32]);
        assert!(orchard.vtx[0].ironwood_actions.is_empty());
        assert_eq!(
            orchard
                .chain_metadata
                .unwrap()
                .ironwood_commitment_tree_size,
            15
        );

        let nullifiers = project_block(
            record.to_proto(),
            PoolSelection::from_request(&[]).unwrap(),
            true,
        );
        assert_eq!(nullifiers.vtx[0].spends[0].nf, vec![7; 32]);
        assert!(nullifiers.vtx[0].outputs.is_empty());
        assert!(nullifiers.vtx[0].actions[0].cmx.is_empty());
        assert!(nullifiers.vtx[0].ironwood_actions[0].ciphertext.is_empty());
        assert_eq!(
            nullifiers.chain_metadata.unwrap(),
            proto::ChainMetadata::default()
        );

        let transparent =
            PoolSelection::from_request(&[proto::PoolType::Transparent as i32]).unwrap();
        assert!(transparent.transparent);
        assert!(!transparent.is_all());
        assert_eq!(
            PoolSelection::from_request(&[99]).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
    }

    #[test]
    fn mempool_projection_matches_the_block_projection_and_flattens_the_index() {
        let mut saw_mined_index = false;
        for encoded in [&*BLOCK_MAINNET_949496_BYTES, &*BLOCK_TESTNET_1842421_BYTES] {
            let block = Block::zcash_deserialize(encoded.as_slice()).unwrap();
            let parsed = parse_block(&RawIndexBlock {
                height: block.coinbase_height().unwrap(),
                hash: block.hash(),
                bytes: encoded.to_vec(),
                txids: block
                    .transactions
                    .iter()
                    .map(|transaction| transaction.hash())
                    .collect(),
            })
            .unwrap();
            let record = CompactBlockRecord {
                height: parsed.height,
                hash: parsed.hash,
                previous_hash: parsed.previous_hash,
                time: parsed.time,
                transactions: parsed.transactions,
                end_tree_sizes: TreeSizes::default(),
            };
            let mined = project_block(record.to_proto(), all_pools(), false);

            let shielded: Vec<&Transaction> = block
                .transactions
                .iter()
                .filter(|transaction| {
                    mined
                        .vtx
                        .iter()
                        .any(|compact| compact.txid == transaction.hash().0.to_vec())
                })
                .map(|transaction| transaction.as_ref())
                .collect();
            let entries: Vec<(Vec<u8>, transaction::Hash)> = shielded
                .iter()
                .map(|transaction| entry(transaction))
                .collect();
            let compact = compact_mempool_txs(&entries, all_pools(), &[]).unwrap();

            assert_eq!(compact.len(), mined.vtx.len());
            assert!(!compact.is_empty());
            for (mempool, mined) in compact.iter().zip(&mined.vtx) {
                saw_mined_index |= mined.index != 0;
                assert_eq!(mempool.index, 0);
                assert_eq!(
                    mempool,
                    &proto::CompactTx {
                        index: 0,
                        ..mined.clone()
                    }
                );
            }
            for (mempool, transaction) in compact.iter().zip(&shielded) {
                assert_shielded_fields(mempool, transaction);
            }
        }
        assert!(saw_mined_index);
    }

    fn assert_shielded_fields(compact: &proto::CompactTx, transaction: &Transaction) {
        let outputs: Vec<_> = transaction.sapling_outputs().collect();
        assert_eq!(compact.outputs.len(), outputs.len());
        for (compact, output) in compact.outputs.iter().zip(outputs) {
            let encrypted: [u8; 580] = output.enc_ciphertext.into();
            assert_eq!(compact.cmu, output.cm_u.to_bytes().to_vec());
            let ephemeral_key: [u8; 32] = (&output.ephemeral_key).into();
            assert_eq!(compact.ephemeral_key, ephemeral_key.to_vec());
            assert_eq!(compact.ciphertext, encrypted[..52].to_vec());
        }

        let actions: Vec<_> = transaction.orchard_actions().collect();
        assert_eq!(compact.actions.len(), actions.len());
        for (compact, action) in compact.actions.iter().zip(actions) {
            let nullifier: [u8; 32] = action.nullifier.into();
            let commitment: [u8; 32] = action.cm_x.into();
            let encrypted: [u8; 580] = action.enc_ciphertext.into();
            assert_eq!(compact.nullifier, nullifier.to_vec());
            assert_eq!(compact.cmx, commitment.to_vec());
            assert_eq!(compact.ciphertext, encrypted[..52].to_vec());
        }
    }

    #[test]
    fn mempool_projection_prunes_the_pools_the_client_did_not_request() {
        let sapling = shielded_transaction(&BLOCK_MAINNET_949496_BYTES, |transaction| {
            transaction.sapling_outputs().next().is_some()
        });
        let orchard = shielded_transaction(&BLOCK_TESTNET_1842421_BYTES, |transaction| {
            transaction.orchard_actions().next().is_some()
        });
        let transactions = vec![entry(&sapling), entry(&orchard)];

        let pools = PoolSelection::from_request(&[proto::PoolType::Orchard as i32]).unwrap();
        let compact = compact_mempool_txs(&transactions, pools, &[]).unwrap();

        assert_eq!(compact.len(), 1);
        assert_eq!(compact[0].txid, orchard.hash().0.to_vec());
        assert!(compact[0].outputs.is_empty());
        assert!(compact[0].spends.is_empty());
        assert!(!compact[0].actions.is_empty());

        let pools = PoolSelection::from_request(&[proto::PoolType::Ironwood as i32]).unwrap();
        assert!(
            compact_mempool_txs(&transactions, pools, &[])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn mempool_transparent_fields_are_opt_in_and_preserve_wire_values() {
        use zakura_chain::transparent;

        let prevout = (0..32).collect::<Vec<u8>>();
        let transparent = Transaction::V1 {
            inputs: vec![transparent::Input::PrevOut {
                outpoint: transparent::OutPoint {
                    hash: transaction::Hash(prevout.clone().try_into().unwrap()),
                    index: 7,
                },
                unlock_script: transparent::Script::new(&[]),
                sequence: u32::MAX,
            }],
            outputs: vec![transparent::Output {
                value: 123_u64.try_into().unwrap(),
                lock_script: transparent::Script::new(&[0x51]),
            }],
            lock_time: transaction::LockTime::unlocked(),
        };
        let orchard = shielded_transaction(&BLOCK_TESTNET_1842421_BYTES, |tx| {
            tx.orchard_actions().next().is_some()
        });
        let entries = [entry(&transparent), entry(&orchard)];
        let legacy = compact_mempool_txs(&entries, all_pools(), &[]).unwrap();
        assert_eq!(legacy.len(), 1);
        assert!(legacy[0].vin.is_empty() && legacy[0].vout.is_empty());

        for types in [
            vec![proto::PoolType::Transparent as i32],
            vec![
                proto::PoolType::Transparent as i32,
                proto::PoolType::Orchard as i32,
            ],
        ] {
            let pools = PoolSelection::from_mempool_request(&types).unwrap();
            let compact = compact_mempool_txs(&entries, pools, &[]).unwrap();
            let mut block = proto::CompactBlock {
                vtx: legacy.clone(),
                ..Default::default()
            };
            block.vtx[0].index = 1;
            let mut block = project_block(block, pools, false);
            add_transparent_txs(
                &mut block,
                &[transparent.clone().into(), orchard.clone().into()],
            );
            let mut expected = compact.clone();
            if expected.len() > 1 {
                expected[1].index = 1;
            }
            assert_eq!(block.vtx, expected);
            assert_eq!(
                compact[0],
                proto::CompactTx {
                    txid: transparent.hash().0.to_vec(),
                    vin: vec![proto::CompactTxIn {
                        prevout_txid: prevout.clone(),
                        prevout_index: 7
                    }],
                    vout: vec![proto::TxOut {
                        value: 123,
                        script_pub_key: vec![0x51]
                    }],
                    ..Default::default()
                }
            );
            assert!(compact.iter().all(|tx| tx.spends.is_empty()
                && tx.outputs.is_empty()
                && tx.ironwood_actions.is_empty()));
            if types.len() == 1 {
                assert!(compact.iter().all(|tx| tx.actions.is_empty()));
            } else {
                assert_eq!(compact[1].actions, legacy[0].actions);
            }
        }
        for invalid in [0, 99] {
            assert!(PoolSelection::from_mempool_request(&[invalid]).is_err());
        }
    }

    #[test]
    fn mempool_exclusions_drop_unambiguous_suffixes_only() {
        let orchard = shielded_transaction(&BLOCK_TESTNET_1842421_BYTES, |transaction| {
            transaction.orchard_actions().next().is_some()
        });
        let bytes = orchard.zcash_serialize_to_vec().unwrap();
        let mut shared = [3; 32];
        shared[31] = 2;
        let transactions = vec![
            (bytes.clone(), transaction::Hash([1; 32])),
            (bytes.clone(), transaction::Hash([2; 32])),
            (bytes, transaction::Hash(shared)),
        ];
        let txids = |compact: Vec<proto::CompactTx>| {
            compact
                .into_iter()
                .map(|transaction| transaction.txid)
                .collect::<Vec<_>>()
        };

        assert_eq!(
            txids(compact_mempool_txs(&transactions, all_pools(), &[vec![1]]).unwrap()),
            [vec![2; 32], shared.to_vec()]
        );
        assert_eq!(
            txids(compact_mempool_txs(&transactions, all_pools(), &[vec![1; 32]]).unwrap()),
            [vec![2; 32], shared.to_vec()]
        );

        let every = [vec![1; 32], vec![2; 32], shared.to_vec()];
        assert_eq!(
            txids(compact_mempool_txs(&transactions, all_pools(), &[vec![2]]).unwrap()),
            every
        );
        assert_eq!(
            txids(compact_mempool_txs(&transactions, all_pools(), &[Vec::new(), vec![9]]).unwrap()),
            every
        );
        assert_eq!(
            txids(
                compact_mempool_txs(&transactions, all_pools(), &[vec![1], vec![3, 3, 2]]).unwrap()
            ),
            [vec![2; 32]]
        );
    }

    #[test]
    fn suffix_lookup_handles_every_length_and_mempool_boundary() {
        let txids: Vec<Digest> = (0..8)
            .map(|i| {
                let mut txid = std::array::from_fn(|j| i + j as u8);
                txid[31] = i % 2;
                txid
            })
            .collect();
        for count in 0..=txids.len() {
            for txid in &txids {
                for len in 0..=32 {
                    let suffix = txid[32 - len..].to_vec();
                    let matches: Vec<_> = txids[..count]
                        .iter()
                        .filter(|id| id.ends_with(&suffix))
                        .copied()
                        .collect();
                    let expected = if matches.len() == 1 {
                        HashSet::from([matches[0]])
                    } else {
                        HashSet::new()
                    };
                    assert_eq!(
                        excluded_txids(
                            txids[..count].iter().rev().copied(),
                            &[suffix.clone(), suffix, vec![0xff], vec![0; 33]]
                        ),
                        expected
                    );
                }
            }
        }
    }

    #[test]
    fn unparsable_mempool_transactions_fail_the_request_unless_excluded() {
        let orchard = shielded_transaction(&BLOCK_TESTNET_1842421_BYTES, |transaction| {
            transaction.orchard_actions().next().is_some()
        });
        let unparsable = (vec![1, 0, 0, 0, 0xff], transaction::Hash([4; 32]));
        let transactions = vec![entry(&orchard), unparsable];

        let status = compact_mempool_txs(&transactions, all_pools(), &[]).unwrap_err();
        assert_eq!(status.code(), tonic::Code::Internal);
        assert!(status.message().contains("unparsable"));

        let compact = compact_mempool_txs(&transactions, all_pools(), &[vec![4; 32]]).unwrap();
        assert_eq!(
            compact
                .into_iter()
                .map(|transaction| transaction.txid)
                .collect::<Vec<_>>(),
            [orchard.hash().0.to_vec()]
        );
    }

    #[test]
    fn an_empty_mempool_projects_to_nothing() {
        assert!(
            compact_mempool_txs(&[], all_pools(), &[vec![1]])
                .unwrap()
                .is_empty()
        );
    }

    fn all_pools() -> PoolSelection {
        PoolSelection::from_request(&[]).unwrap()
    }

    fn entry(transaction: &Transaction) -> (Vec<u8>, transaction::Hash) {
        (
            transaction.zcash_serialize_to_vec().unwrap(),
            transaction.hash(),
        )
    }

    fn shielded_transaction(block: &[u8], shielded: impl Fn(&Transaction) -> bool) -> Transaction {
        Block::zcash_deserialize(block)
            .unwrap()
            .transactions
            .iter()
            .find(|transaction| shielded(transaction))
            .map(|transaction| (**transaction).clone())
            .expect("the block vector holds a shielded transaction")
    }

    fn action(byte: u8) -> CompactShieldedAction {
        CompactShieldedAction {
            nullifier: [byte; 32],
            commitment: [byte; 32],
            ephemeral_key: [byte; 32],
            ciphertext: [byte; 52],
        }
    }
}
