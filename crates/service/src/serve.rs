//! Compact index record projection, shielded-pool filtering, and protobuf response construction.

use std::collections::HashSet;

use prost::bytes::Bytes;
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

/// The block identity stored beside an encoded payload, which the payload must repeat.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Envelope<'a> {
    pub(crate) height: u32,
    pub(crate) hash: &'a Digest,
    pub(crate) previous_hash: &'a Digest,
}

/// [`project_block`] for an encoded block, without decoding it.
///
/// Accepts only the exact layout the index writes: prost's canonical encoding (one-byte
/// keys, minimal varints, no zero scalars, fields in tag order) with 32- and 52-byte
/// shielded fields. `Some(out)` therefore means that decoding `block` succeeds, that it
/// repeats `envelope` and has chain metadata (the checks the decoding path makes), and
/// that `out` is the encoding of the projected block. When nothing is removed, `out` is
/// `block` itself. Anything else returns `None` so the caller can decode instead.
pub(crate) fn project_encoded(
    block: &Bytes,
    envelope: Envelope<'_>,
    pools: PoolSelection,
    nullifiers: bool,
) -> Option<Bytes> {
    // The first pass validates and sizes the output; the second writes it.
    let mut tx_lens = Vec::new();
    let (len, changed) = walk_block(block, envelope, pools, nullifiers, &mut tx_lens, None)?;
    if !changed {
        return Some(block.clone());
    }
    let mut out = Vec::with_capacity(len);
    walk_block(
        block,
        envelope,
        pools,
        nullifiers,
        &mut tx_lens,
        Some(&mut out),
    )?;
    debug_assert_eq!(out.len(), len);
    Some(out.into())
}

const NULLIFIER_FIELD: usize = 2 + 32;
/// Marks a transaction [`project_block`] drops in `walk_block`'s recorded lengths.
const DROPPED: usize = usize::MAX;
const CHAIN_METADATA_FIELD: u8 = 8 << 3 | 2;

/// Validates `block` and returns the projected length and whether it differs from the
/// input. Without `out`, it records each kept transaction's projected length in
/// `tx_lens`; with `out`, it writes the projection using those lengths.
fn walk_block(
    mut block: &[u8],
    envelope: Envelope<'_>,
    pools: PoolSelection,
    nullifiers: bool,
    tx_lens: &mut Vec<usize>,
    mut out: Option<&mut Vec<u8>>,
) -> Option<(usize, bool)> {
    let mut written_txs = 0;
    let (mut len, mut changed) = (0, nullifiers);
    let (mut height, mut hash, mut previous_hash, mut metadata) = (0, None, None, false);
    let mut previous = 0;
    while !block.is_empty() {
        let field = next_field(&mut block)?;
        // Tag order; only transactions repeat.
        if field.number < previous || (field.number == previous && field.number != 7) {
            return None;
        }
        previous = field.number;
        match (field.number, field.value) {
            (2, Value::Varint(value)) if value != 0 => height = value,
            (3, Value::Bytes(value)) => hash = Some(value),
            (4, Value::Bytes(value)) => previous_hash = Some(value),
            (5, Value::Varint(value)) if value != 0 && value <= u64::from(u32::MAX) => {}
            (6, Value::Bytes(value)) if !value.is_empty() => {}
            (7, Value::Bytes(tx)) => {
                let tx_len = match out.as_deref_mut() {
                    None => {
                        let projected = project_tx(tx, pools, nullifiers)?;
                        changed |= projected.changed || !projected.keep;
                        let tx_len = if projected.keep {
                            projected.len
                        } else {
                            DROPPED
                        };
                        tx_lens.push(tx_len);
                        tx_len
                    }
                    Some(out) => {
                        let tx_len = *tx_lens.get(written_txs)?;
                        written_txs += 1;
                        if tx_len != DROPPED {
                            out.push(field.raw[0]);
                            prost::encoding::encode_varint(tx_len as u64, out);
                            write_tx(tx, pools, nullifiers, out);
                        }
                        tx_len
                    }
                };
                if tx_len != DROPPED {
                    len += 1 + prost::encoding::encoded_len_varint(tx_len as u64) + tx_len;
                }
                continue;
            }
            (8, Value::Bytes(value)) if is_chain_metadata(value) => {
                metadata = true;
                if nullifiers {
                    continue;
                }
            }
            _ => return None,
        }
        len += field.raw.len();
        if let Some(out) = out.as_deref_mut() {
            out.extend_from_slice(field.raw);
        }
    }
    if height != u64::from(envelope.height)
        || hash != Some(envelope.hash.as_slice())
        || previous_hash != Some(envelope.previous_hash.as_slice())
        || !metadata
    {
        return None;
    }
    if nullifiers {
        // project_block replaces chain metadata with an empty message, which is last.
        len += 2;
        if let Some(out) = out {
            out.extend_from_slice(&[CHAIN_METADATA_FIELD, 0]);
        }
    }
    Some((len, changed))
}

struct ProjectedTx {
    len: usize,
    /// Whether [`project_block`] keeps the transaction.
    keep: bool,
    /// Whether the kept transaction differs from its input.
    changed: bool,
}

/// Validates a transaction and measures its projection.
fn project_tx(mut tx: &[u8], pools: PoolSelection, nullifiers: bool) -> Option<ProjectedTx> {
    let (mut len, mut shielded, mut changed) = (0, false, false);
    let mut previous = 0;
    while !tx.is_empty() {
        let field = next_field(&mut tx)?;
        // Tag order is 1-6 then 9; vin/vout (7, 8) never occur in the compact index.
        let rank = match field.number {
            1..=6 => field.number,
            9 => 7,
            _ => return None,
        };
        if rank < previous || (rank == previous && rank < 4) {
            return None;
        }
        previous = rank;
        let keep = match (field.number, field.value) {
            (1, Value::Varint(value)) if value != 0 => true,
            (2, Value::Bytes(value)) if !value.is_empty() => true,
            (3, Value::Varint(value)) if value != 0 && value <= u64::from(u32::MAX) => true,
            (4, Value::Bytes(value)) if is_spend(value) => pools.sapling,
            (5, Value::Bytes(value)) if is_output(value) => pools.sapling && !nullifiers,
            (6, Value::Bytes(value)) if is_action(value) => pools.orchard,
            (9, Value::Bytes(value)) if is_action(value) => pools.ironwood,
            _ => return None,
        };
        if !keep {
            changed = true;
            continue;
        }
        shielded |= field.number >= 4;
        if nullifiers && matches!(field.number, 6 | 9) {
            changed = true;
            len += 2 + NULLIFIER_FIELD;
        } else {
            len += field.raw.len();
        }
    }
    Some(ProjectedTx {
        len,
        keep: shielded || nullifiers,
        changed,
    })
}

/// Writes the projection of a transaction [`project_tx`] has validated, so it only
/// selects and copies fields.
fn write_tx(mut tx: &[u8], pools: PoolSelection, nullifiers: bool, out: &mut Vec<u8>) {
    while let Some(field) = next_field(&mut tx) {
        let keep = match field.number {
            4 => pools.sapling,
            5 => pools.sapling && !nullifiers,
            6 => pools.orchard,
            9 => pools.ironwood,
            _ => true,
        };
        match field.value {
            Value::Bytes(action) if keep && nullifiers && matches!(field.number, 6 | 9) => {
                // project_block keeps only the nullifier, the action's first field.
                out.extend_from_slice(&[field.raw[0], NULLIFIER_FIELD as u8]);
                out.extend_from_slice(&action[..NULLIFIER_FIELD]);
            }
            _ if keep => out.extend_from_slice(field.raw),
            _ => {}
        }
    }
}

// The index's fixed layouts: every field present, 32 bytes except 52-byte ciphertexts.
fn is_spend(value: &[u8]) -> bool {
    has_layout(value, &[(0x0a, 32)])
}

fn is_output(value: &[u8]) -> bool {
    has_layout(value, &[(0x0a, 32), (0x12, 32), (0x1a, 52)])
}

fn is_action(value: &[u8]) -> bool {
    has_layout(value, &[(0x0a, 32), (0x12, 32), (0x1a, 32), (0x22, 52)])
}

fn has_layout(mut value: &[u8], fields: &[(u8, u8)]) -> bool {
    fields.iter().all(|&(key, len)| {
        let field_len = 2 + usize::from(len);
        let matches = value.len() >= field_len && value[0] == key && value[1] == len;
        if matches {
            value = &value[field_len..];
        }
        matches
    }) && value.is_empty()
}

/// Canonical `ChainMetadata`: uint32 fields 1-3 in order, each nonzero.
fn is_chain_metadata(mut value: &[u8]) -> bool {
    let mut previous = 0;
    while !value.is_empty() {
        match next_field(&mut value) {
            Some(Field {
                number: number @ 1..=3,
                value: Value::Varint(size),
                ..
            }) if number > previous && size != 0 && size <= u64::from(u32::MAX) => {
                previous = number;
            }
            _ => return false,
        }
    }
    true
}

#[derive(Clone, Copy)]
enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

/// One canonically encoded varint or length-delimited field.
struct Field<'a> {
    number: u8,
    /// The field including its key, for copying verbatim.
    raw: &'a [u8],
    value: Value<'a>,
}

/// Reads one field, or `None` for anything prost would not have written.
fn next_field<'a>(reader: &mut &'a [u8]) -> Option<Field<'a>> {
    let start = *reader;
    let key = *reader.first()?;
    // Every field number in this schema is below 16, so canonical keys are one byte.
    if key >= 0x80 {
        return None;
    }
    *reader = &reader[1..];
    let value = match key & 7 {
        0 => Value::Varint(canonical_varint(reader)?),
        2 => {
            let len = usize::try_from(canonical_varint(reader)?).ok()?;
            if len > reader.len() {
                return None;
            }
            let (value, rest) = reader.split_at(len);
            *reader = rest;
            Value::Bytes(value)
        }
        _ => return None,
    };
    Some(Field {
        number: key >> 3,
        raw: &start[..start.len() - reader.len()],
        value,
    })
}

/// Reads a minimal LEB128 varint, the only form prost writes.
fn canonical_varint(reader: &mut &[u8]) -> Option<u64> {
    let mut value = 0;
    for (index, &byte) in reader.iter().enumerate().take(10) {
        value |= u64::from(byte & 0x7f) << (7 * index);
        if byte < 0x80 {
            // A final zero byte pads a shorter encoding; a tenth byte above 1 overflows.
            if (index > 0 && byte == 0) || (index == 9 && byte > 1) {
                return None;
            }
            *reader = &reader[index + 1..];
            return Some(value);
        }
    }
    None
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

    /// The decoding path [`project_encoded`] replaces: decode, make the checks
    /// `ProtobufBlockRecord::decode` makes, project and re-encode.
    fn decoded_projection(
        encoded: &[u8],
        envelope: Envelope<'_>,
        pools: PoolSelection,
        nullifiers: bool,
    ) -> Option<Vec<u8>> {
        use prost::Message as _;

        let block = proto::CompactBlock::decode(encoded).ok()?;
        (block.height == u64::from(envelope.height)
            && block.hash == envelope.hash
            && block.prev_hash == envelope.previous_hash
            && block.chain_metadata.is_some())
        .then(|| project_block(block, pools, nullifiers).encode_to_vec())
    }

    /// Every pool selection, with and without nullifier projection.
    fn selections() -> Vec<(PoolSelection, bool)> {
        let pools = [
            proto::PoolType::Sapling,
            proto::PoolType::Orchard,
            proto::PoolType::Ironwood,
        ];
        (0..8u8)
            .flat_map(|mask| {
                let selected = pools
                    .iter()
                    .enumerate()
                    .filter(|(bit, _)| mask & (1 << bit) != 0)
                    .map(|(_, pool)| *pool as i32)
                    .collect::<Vec<_>>();
                let selection = PoolSelection::from_request(&selected).unwrap();
                [(selection, false), (selection, true)]
            })
            .collect()
    }

    fn record_envelope(record: &CompactBlockRecord) -> Envelope<'_> {
        Envelope {
            height: record.height,
            hash: &record.hash,
            previous_hash: &record.previous_hash,
        }
    }

    fn encode_record(record: &CompactBlockRecord) -> Bytes {
        use prost::Message as _;
        record.to_proto().encode_to_vec().into()
    }

    #[test]
    fn encoded_projection_is_byte_identical_to_decoding() {
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

        for record in &records {
            let encoded = encode_record(record);
            let envelope = record_envelope(record);
            for (pools, nullifiers) in selections() {
                let actual = project_encoded(&encoded, envelope, pools, nullifiers)
                    .expect("index records take the fast path");
                assert_eq!(
                    Some(actual.to_vec()),
                    decoded_projection(&encoded, envelope, pools, nullifiers),
                    "{pools:?} nullifiers={nullifiers}"
                );
                if pools.is_all() && !nullifiers {
                    // Nothing is removed, so the stored bytes are returned without a copy.
                    assert_eq!(actual.as_ptr(), encoded.as_ptr());
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

        fn digest<const N: usize>(&mut self) -> [u8; N] {
            std::array::from_fn(|_| self.next() as u8)
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

        /// A record shaped like the index's, including payload-less transactions.
        fn record(&mut self) -> CompactBlockRecord {
            let action = |rng: &mut Rng| CompactShieldedAction {
                nullifier: rng.digest(),
                commitment: rng.digest(),
                ephemeral_key: rng.digest(),
                ciphertext: rng.digest(),
            };
            CompactBlockRecord {
                height: self.scalar() as u32,
                hash: self.digest(),
                previous_hash: self.digest(),
                time: self.scalar() as u32,
                transactions: (0..self.below(5))
                    .map(|_| CompactTransaction {
                        index: self.scalar(),
                        txid: self.digest(),
                        sapling_spends: (0..self.count()).map(|_| self.digest()).collect(),
                        sapling_outputs: (0..self.count())
                            .map(|_| CompactSaplingOutput {
                                cmu: self.digest(),
                                ephemeral_key: self.digest(),
                                ciphertext: self.digest(),
                            })
                            .collect(),
                        orchard_actions: (0..self.count()).map(|_| action(self)).collect(),
                        ironwood_actions: (0..self.count()).map(|_| action(self)).collect(),
                    })
                    .collect(),
                end_tree_sizes: TreeSizes {
                    sapling: self.scalar() as u32,
                    orchard: self.scalar() as u32,
                    ironwood: self.scalar() as u32,
                },
            }
        }
    }

    #[test]
    fn encoded_projection_takes_the_fast_path_for_every_index_record() {
        let mut rng = Rng(20_261_016);
        for _ in 0..3_000 {
            let record = rng.record();
            let encoded = encode_record(&record);
            let envelope = record_envelope(&record);
            for (pools, nullifiers) in selections() {
                assert_eq!(
                    project_encoded(&encoded, envelope, pools, nullifiers).map(|out| out.to_vec()),
                    Some(decoded_projection(&encoded, envelope, pools, nullifiers).unwrap()),
                    "{record:?} {pools:?} nullifiers={nullifiers}"
                );
            }
        }
    }

    #[test]
    fn encoded_projection_agrees_with_decoding_whenever_it_answers() {
        use prost::Message as _;

        let mut rng = Rng(7);
        let (mut answered, mut declined) = (0, 0);
        let mut check = |encoded: &Bytes, envelope: Envelope<'_>| {
            for (pools, nullifiers) in selections() {
                match project_encoded(encoded, envelope, pools, nullifiers) {
                    Some(actual) => {
                        answered += 1;
                        assert_eq!(
                            Some(actual.to_vec()),
                            decoded_projection(encoded, envelope, pools, nullifiers),
                            "{encoded:02x?} {pools:?} nullifiers={nullifiers}"
                        );
                    }
                    None => declined += 1,
                }
            }
        };

        // Arbitrary blocks, beyond anything the index writes.
        for _ in 0..1_000 {
            let action = |rng: &mut Rng| proto::CompactOrchardAction {
                nullifier: rng.bytes(),
                cmx: rng.bytes(),
                ephemeral_key: rng.bytes(),
                ciphertext: rng.bytes(),
            };
            let block = proto::CompactBlock {
                height: rng.scalar(),
                hash: rng.bytes(),
                prev_hash: rng.bytes(),
                time: rng.scalar() as u32,
                header: rng.bytes(),
                vtx: (0..rng.below(4))
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
                        vin: Vec::new(),
                        vout: Vec::new(),
                    })
                    .collect(),
                chain_metadata: (rng.below(4) != 0).then(|| proto::ChainMetadata {
                    sapling_commitment_tree_size: rng.scalar() as u32,
                    orchard_commitment_tree_size: rng.scalar() as u32,
                    ironwood_commitment_tree_size: rng.scalar() as u32,
                }),
            };
            let digest = |bytes: &[u8]| -> Digest {
                std::array::from_fn(|i| bytes.get(i).copied().unwrap_or(0))
            };
            let (hash, previous_hash) = (digest(&block.hash), digest(&block.prev_hash));
            let envelope = Envelope {
                height: block.height as u32,
                hash: &hash,
                previous_hash: &previous_hash,
            };
            check(&block.encode_to_vec().into(), envelope);
        }

        // Index records with corrupted bytes: flipped, replaced, inserted, removed or cut.
        for _ in 0..3_000 {
            let record = rng.record();
            let mut bytes = encode_record(&record).to_vec();
            for _ in 0..=rng.below(3) {
                if bytes.is_empty() {
                    break;
                }
                let at = rng.below(bytes.len() as u64) as usize;
                match rng.below(5) {
                    0 => bytes[at] ^= 1 << rng.below(8),
                    1 => bytes[at] = rng.next() as u8,
                    2 => bytes.insert(at, rng.next() as u8),
                    3 => {
                        bytes.remove(at);
                    }
                    _ => bytes.truncate(at),
                }
            }
            check(&bytes.into(), record_envelope(&record));
        }
        // Both outcomes occur, so neither half of the property holds vacuously.
        assert!(
            answered > 5_000 && declined > 5_000,
            "{answered} {declined}"
        );
    }

    #[test]
    fn canonical_varints_round_trip_and_reject_padding() {
        let mut rng = Rng(3);
        let values = (0..64)
            .flat_map(|bit| [1u64 << bit, (1u64 << bit) - 1])
            .chain([0, u64::MAX])
            .chain((0..10_000).map(|_| rng.next() >> rng.below(64)));
        for value in values {
            let mut encoded = Vec::new();
            prost::encoding::encode_varint(value, &mut encoded);
            encoded.push(0xaa);
            let mut reader = encoded.as_slice();
            assert_eq!(canonical_varint(&mut reader), Some(value));
            assert_eq!(reader, [0xaa]);

            // The same value with a redundant trailing zero group.
            let mut padded = encoded[..encoded.len() - 1].to_vec();
            if padded.len() < 10 {
                *padded.last_mut().unwrap() |= 0x80;
                padded.push(0);
                assert_eq!(canonical_varint(&mut padded.as_slice()), None, "{value}");
            }
        }
        for overflowing in [
            [0xff; 9].iter().copied().chain([2]).collect::<Vec<_>>(),
            vec![0x80; 10],
            vec![0x80; 11],
            vec![0x80],
            vec![],
        ] {
            assert_eq!(canonical_varint(&mut overflowing.as_slice()), None);
        }
    }

    #[test]
    fn encoded_projection_declines_non_canonical_or_invalid_input() {
        use prost::Message as _;

        let block = proto::CompactBlock {
            height: 1,
            hash: vec![1; 32],
            prev_hash: vec![2; 32],
            time: 3,
            vtx: vec![proto::CompactTx {
                index: 1,
                txid: vec![2; 32],
                actions: vec![proto::CompactOrchardAction {
                    nullifier: vec![3; 32],
                    cmx: vec![4; 32],
                    ephemeral_key: vec![5; 32],
                    ciphertext: vec![6; 52],
                }],
                ..Default::default()
            }],
            chain_metadata: Some(proto::ChainMetadata::default()),
            ..Default::default()
        };
        let (hash, previous_hash) = ([1; 32], [2; 32]);
        let envelope = Envelope {
            height: 1,
            hash: &hash,
            previous_hash: &previous_hash,
        };
        let pools = PoolSelection::from_request(&[]).unwrap();
        let encoded = block.encode_to_vec();
        assert!(project_encoded(&encoded.clone().into(), envelope, pools, true).is_some());

        let with_vin = proto::CompactBlock {
            vtx: vec![proto::CompactTx {
                vin: vec![proto::CompactTxIn::default()],
                ..block.vtx[0].clone()
            }],
            ..block.clone()
        };
        let with = |bytes: &[u8]| [&encoded[..], bytes].concat();
        let cases: [(&str, Vec<u8>); 11] = [
            ("vin", with_vin.encode_to_vec()),
            // Height (field 2, two bytes) moved after chain metadata.
            ("out of order", [&encoded[2..], &encoded[..2]].concat()),
            ("unknown field", with(&[0x48, 1])),
            ("wrong wire type", [&[0x12][..], &encoded[1..]].concat()),
            ("truncated", encoded[..encoded.len() - 1].to_vec()),
            (
                "overlong varint",
                [&[0x10, 0x81, 0x00][..], &encoded[2..]].concat(),
            ),
            // Time (field 5) is bytes 70..72, after height and both hashes.
            (
                "explicit zero",
                [&encoded[..70], &[0x28, 0][..], &encoded[72..]].concat(),
            ),
            ("bad nested output", {
                let mut tx = proto::CompactTx::default().encode_to_vec();
                tx.extend_from_slice(&[0x2a, 2, 0x0f, 1]);
                let mut bytes = encoded[..encoded.len() - 2].to_vec();
                bytes.push(0x3a);
                bytes.push(tx.len() as u8);
                bytes.extend_from_slice(&tx);
                bytes.extend_from_slice(&[0x42, 0]);
                bytes
            }),
            (
                "bad chain metadata",
                [&encoded[..encoded.len() - 2], &[0x42, 1, 0xff]].concat(),
            ),
            ("no chain metadata", encoded[..encoded.len() - 2].to_vec()),
            (
                "explicit empty metadata field",
                [&encoded[..encoded.len() - 1], &[2, 0x08, 0]].concat(),
            ),
        ];
        for (name, input) in cases {
            let input: Bytes = input.into();
            for nullifiers in [false, true] {
                assert!(
                    project_encoded(&input, envelope, pools, nullifiers).is_none(),
                    "{name}"
                );
            }
        }

        let other = [9; 32];
        for envelope in [
            Envelope {
                height: 2,
                ..envelope
            },
            Envelope {
                hash: &other,
                ..envelope
            },
            Envelope {
                previous_hash: &other,
                ..envelope
            },
        ] {
            assert!(project_encoded(&encoded.clone().into(), envelope, pools, false).is_none());
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
