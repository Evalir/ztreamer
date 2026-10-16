//! Lossless conversion between index records and the existing compact-block schema.

use ztreamer_protocol::{compact_bytes, proto};

use crate::{
    codec::{CodecError, CompactBlockRecord, TreeSizes},
    parser::{CompactSaplingOutput, CompactShieldedAction, CompactTransaction},
};

impl CompactBlockRecord {
    pub fn to_proto(&self) -> proto::CompactBlock {
        proto::CompactBlock {
            height: self.height.into(),
            hash: self.hash.to_vec(),
            prev_hash: self.previous_hash.to_vec(),
            time: self.time,
            header: Vec::new(),
            vtx: self.transactions.iter().map(transaction).collect(),
            chain_metadata: Some(proto::ChainMetadata {
                sapling_commitment_tree_size: self.end_tree_sizes.sapling,
                orchard_commitment_tree_size: self.end_tree_sizes.orchard,
                ironwood_commitment_tree_size: self.end_tree_sizes.ironwood,
            }),
        }
    }

    /// Exact length of [`Self::encode_proto`]'s output.
    pub(crate) fn proto_len(&self) -> usize {
        let metadata = metadata_len(self.end_tree_sizes);
        uint_len(u64::from(self.height))
            + 2 * BYTES32_FIELD
            + uint_len(u64::from(self.time))
            + self
                .transactions
                .iter()
                .filter(|tx| tx.has_payload())
                .map(|tx| nested_len(transaction_len(tx)))
                .sum::<usize>()
            + nested_len(metadata)
    }

    /// Writes the same bytes as `self.to_proto().encode(..)`, without building the
    /// intermediate message: every fixed-width field would otherwise be its own `Vec`.
    pub(crate) fn encode_proto(&self, buf: &mut Vec<u8>) {
        put_uint(buf, 2, u64::from(self.height));
        put_bytes(buf, 3, &self.hash);
        put_bytes(buf, 4, &self.previous_hash);
        put_uint(buf, 5, u64::from(self.time));
        // Like the index, responses never carry transactions without shielded data.
        for tx in self.transactions.iter().filter(|tx| tx.has_payload()) {
            put_key(buf, 7, LENGTH_DELIMITED, transaction_len(tx));
            put_uint(buf, 1, tx.index);
            put_bytes(buf, 2, &tx.txid);
            for nf in &tx.sapling_spends {
                put_key(buf, 4, LENGTH_DELIMITED, BYTES32_FIELD);
                put_bytes(buf, 1, nf);
            }
            for output in &tx.sapling_outputs {
                put_key(buf, 5, LENGTH_DELIMITED, OUTPUT_LEN);
                put_bytes(buf, 1, &output.cmu);
                put_bytes(buf, 2, &output.ephemeral_key);
                put_bytes(buf, 3, &output.ciphertext);
            }
            for (field, actions) in [(6, &tx.orchard_actions), (9, &tx.ironwood_actions)] {
                for action in actions {
                    put_key(buf, field, LENGTH_DELIMITED, ACTION_LEN);
                    put_bytes(buf, 1, &action.nullifier);
                    put_bytes(buf, 2, &action.commitment);
                    put_bytes(buf, 3, &action.ephemeral_key);
                    put_bytes(buf, 4, &action.ciphertext);
                }
            }
        }
        let trees = self.end_tree_sizes;
        put_key(buf, 8, LENGTH_DELIMITED, metadata_len(trees));
        put_uint(buf, 1, u64::from(trees.sapling));
        put_uint(buf, 2, u64::from(trees.orchard));
        put_uint(buf, 3, u64::from(trees.ironwood));
    }

    pub(crate) fn from_proto(block: compact_bytes::CompactBlock) -> Result<Self, CodecError> {
        let trees = block.chain_metadata.ok_or(CodecError::InvalidRecord)?;
        Ok(Self {
            height: block
                .height
                .try_into()
                .map_err(|_| CodecError::InvalidRecord)?,
            hash: array(block.hash)?,
            previous_hash: array(block.prev_hash)?,
            time: block.time,
            transactions: block
                .vtx
                .into_iter()
                .map(|tx| {
                    Ok(CompactTransaction {
                        index: tx.index,
                        txid: array(tx.txid)?,
                        sapling_spends: tx
                            .spends
                            .into_iter()
                            .map(|spend| array(spend.nf))
                            .collect::<Result<_, _>>()?,
                        sapling_outputs: tx
                            .outputs
                            .into_iter()
                            .map(|output| {
                                Ok(CompactSaplingOutput {
                                    cmu: array(output.cmu)?,
                                    ephemeral_key: array(output.ephemeral_key)?,
                                    ciphertext: array(output.ciphertext)?,
                                })
                            })
                            .collect::<Result<_, CodecError>>()?,
                        orchard_actions: tx
                            .actions
                            .into_iter()
                            .map(decode_action)
                            .collect::<Result<_, _>>()?,
                        ironwood_actions: tx
                            .ironwood_actions
                            .into_iter()
                            .map(decode_action)
                            .collect::<Result<_, _>>()?,
                    })
                })
                .collect::<Result<_, CodecError>>()?,
            end_tree_sizes: TreeSizes {
                sapling: trees.sapling_commitment_tree_size,
                orchard: trees.orchard_commitment_tree_size,
                ironwood: trees.ironwood_commitment_tree_size,
            },
        })
    }
}

pub(crate) fn transaction(tx: &CompactTransaction) -> proto::CompactTx {
    proto::CompactTx {
        index: tx.index,
        txid: tx.txid.to_vec(),
        spends: tx
            .sapling_spends
            .iter()
            .map(|nf| proto::CompactSaplingSpend { nf: nf.to_vec() })
            .collect(),
        outputs: tx
            .sapling_outputs
            .iter()
            .map(|output| proto::CompactSaplingOutput {
                cmu: output.cmu.to_vec(),
                ephemeral_key: output.ephemeral_key.to_vec(),
                ciphertext: output.ciphertext.to_vec(),
            })
            .collect(),
        actions: tx.orchard_actions.iter().map(action).collect(),
        ironwood_actions: tx.ironwood_actions.iter().map(action).collect(),
        ..Default::default()
    }
}

fn action(action: &CompactShieldedAction) -> proto::CompactOrchardAction {
    proto::CompactOrchardAction {
        nullifier: action.nullifier.to_vec(),
        cmx: action.commitment.to_vec(),
        ephemeral_key: action.ephemeral_key.to_vec(),
        ciphertext: action.ciphertext.to_vec(),
    }
}

fn decode_action(
    action: compact_bytes::CompactOrchardAction,
) -> Result<CompactShieldedAction, CodecError> {
    Ok(CompactShieldedAction {
        nullifier: array(action.nullifier)?,
        commitment: array(action.cmx)?,
        ephemeral_key: array(action.ephemeral_key)?,
        ciphertext: array(action.ciphertext)?,
    })
}

// Every field number in this schema is below 16, so each key is one byte.
const VARINT: u8 = 0;
const LENGTH_DELIMITED: u8 = 2;
const BYTES32_FIELD: usize = 2 + 32;
const OUTPUT_LEN: usize = 2 * BYTES32_FIELD + 2 + 52;
const ACTION_LEN: usize = 3 * BYTES32_FIELD + 2 + 52;

fn transaction_len(tx: &CompactTransaction) -> usize {
    uint_len(tx.index)
        + BYTES32_FIELD
        + tx.sapling_spends.len() * nested_len(BYTES32_FIELD)
        + tx.sapling_outputs.len() * nested_len(OUTPUT_LEN)
        + (tx.orchard_actions.len() + tx.ironwood_actions.len()) * nested_len(ACTION_LEN)
}

fn metadata_len(trees: TreeSizes) -> usize {
    uint_len(u64::from(trees.sapling))
        + uint_len(u64::from(trees.orchard))
        + uint_len(u64::from(trees.ironwood))
}

fn nested_len(len: usize) -> usize {
    1 + prost::encoding::encoded_len_varint(len as u64) + len
}

/// Proto3 omits zero scalars.
fn uint_len(value: u64) -> usize {
    if value == 0 {
        0
    } else {
        1 + prost::encoding::encoded_len_varint(value)
    }
}

fn put_key(buf: &mut Vec<u8>, field: u8, wire_type: u8, len: usize) {
    buf.push(field << 3 | wire_type);
    if wire_type == LENGTH_DELIMITED {
        prost::encoding::encode_varint(len as u64, buf);
    }
}

fn put_uint(buf: &mut Vec<u8>, field: u8, value: u64) {
    if value != 0 {
        buf.push(field << 3 | VARINT);
        prost::encoding::encode_varint(value, buf);
    }
}

fn put_bytes(buf: &mut Vec<u8>, field: u8, bytes: &[u8]) {
    put_key(buf, field, LENGTH_DELIMITED, bytes.len());
    buf.extend_from_slice(bytes);
}

fn array<const N: usize>(bytes: impl AsRef<[u8]>) -> Result<[u8; N], CodecError> {
    bytes
        .as_ref()
        .try_into()
        .map_err(|_| CodecError::InvalidRecord)
}

#[cfg(test)]
mod tests {
    use prost::Message as _;
    use zakura_chain::{block::Block, serialization::ZcashDeserialize as _};
    use zakura_test::vectors::{
        BLOCK_MAINNET_949496_BYTES, BLOCK_MAINNET_1687121_BYTES, BLOCK_TESTNET_1842421_BYTES,
    };

    use super::*;
    use crate::parser::{RawIndexBlock, parse_block};

    fn assert_matches_prost(record: &CompactBlockRecord) {
        let mut expected = record.to_proto();
        expected.vtx.retain(|tx| {
            !tx.spends.is_empty()
                || !tx.outputs.is_empty()
                || !tx.actions.is_empty()
                || !tx.ironwood_actions.is_empty()
        });
        let expected = expected.encode_to_vec();
        let mut actual = Vec::new();
        record.encode_proto(&mut actual);
        assert_eq!(actual, expected);
        assert_eq!(record.proto_len(), expected.len());
    }

    fn action(byte: u8) -> CompactShieldedAction {
        CompactShieldedAction {
            nullifier: [byte; 32],
            commitment: [byte.wrapping_add(1); 32],
            ephemeral_key: [byte.wrapping_add(2); 32],
            ciphertext: [byte.wrapping_add(3); 52],
        }
    }

    #[test]
    fn direct_encoding_is_byte_identical_to_prost_for_real_blocks() {
        for bytes in [
            &*BLOCK_MAINNET_949496_BYTES,
            &*BLOCK_MAINNET_1687121_BYTES,
            &*BLOCK_TESTNET_1842421_BYTES,
        ] {
            let block = Block::zcash_deserialize(bytes.as_slice()).unwrap();
            let parsed = parse_block(&RawIndexBlock {
                height: block.coinbase_height().unwrap(),
                hash: block.hash(),
                bytes: bytes.to_vec(),
                txids: block.transactions.iter().map(|tx| tx.hash()).collect(),
            })
            .unwrap();
            assert!(!parsed.transactions.is_empty());
            assert_matches_prost(&CompactBlockRecord {
                height: parsed.height,
                hash: parsed.hash,
                previous_hash: parsed.previous_hash,
                time: parsed.time,
                transactions: parsed.transactions,
                end_tree_sizes: TreeSizes {
                    sapling: 1 << 20,
                    orchard: 300,
                    ironwood: 0,
                },
            });
        }
    }

    #[test]
    fn direct_encoding_is_byte_identical_to_prost_at_varint_boundaries() {
        let scalars = [0, 1, 127, 128, 16_383, 16_384, u32::MAX];
        // Counts that push transaction and block lengths across 1-, 2- and 3-byte varints.
        for count in [0, 1, 2, 3, 104, 105, 106, 1_000] {
            for (i, &scalar) in scalars.iter().enumerate() {
                let tx = CompactTransaction {
                    index: if i == scalars.len() - 1 {
                        u64::MAX
                    } else {
                        u64::from(scalar)
                    },
                    txid: [i as u8; 32],
                    sapling_spends: vec![[3; 32]; count % 7],
                    sapling_outputs: vec![
                        CompactSaplingOutput {
                            cmu: [4; 32],
                            ephemeral_key: [5; 32],
                            ciphertext: [6; 52],
                        };
                        count % 5
                    ],
                    orchard_actions: (0..count).map(|n| action(n as u8)).collect(),
                    ironwood_actions: (0..count / 2).map(|n| action(!n as u8)).collect(),
                };
                let empty = CompactTransaction {
                    index: 9,
                    txid: [9; 32],
                    sapling_spends: vec![],
                    sapling_outputs: vec![],
                    orchard_actions: vec![],
                    ironwood_actions: vec![],
                };
                assert_matches_prost(&CompactBlockRecord {
                    height: scalar,
                    hash: [1; 32],
                    previous_hash: [2; 32],
                    time: scalars[scalars.len() - 1 - i],
                    transactions: vec![empty.clone(), tx.clone(), empty, tx],
                    end_tree_sizes: TreeSizes {
                        sapling: scalar,
                        orchard: scalars[(i + 1) % scalars.len()],
                        ironwood: scalars[(i + 2) % scalars.len()],
                    },
                });
            }
        }
    }
}
