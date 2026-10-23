//! The chain-state seam: everything [`CompactService`](crate::CompactService) needs that is not
//! in the compact index.
//!
//! The compact index answers block and range requests. Everything else, from transparent address
//! lookups to tree states to the mempool, comes from a node. Today that node is the embedded
//! Zakura, reached in-process through its `ReadStateService` and the mempool handle; that is
//! [`InProcessBackend`]. A backend over a remote node's JSON-RPC implements the same trait.
//!
//! The trait returns plain data, not Zakura's `ReadResponse` variants, so a remote backend can
//! fill it from RPC answers without building Zakura state types.

use std::{collections::HashSet, ops::RangeInclusive, sync::Arc};

use tonic::Status;
use tower::ServiceExt as _;
use zakura_chain::{
    block::{self, Block},
    parameters::Network,
    serialization::ZcashSerialize as _,
    subtree::NoteCommitmentSubtreeIndex,
    transaction::{self, Transaction, UnminedTx},
    transparent,
};
use zakura_state::{ChainTipChange, ReadRequest, ReadResponse, ReadStateService};
use ztreamer_node::NodeClient;

/// Why a backend request failed. Each variant maps to one gRPC status code.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BackendError {
    /// The backend cannot answer now: the node is unreachable, a read failed, or this backend
    /// has no node handle for the request. Maps to `UNAVAILABLE`.
    #[error("{0}")]
    Unavailable(String),
    /// The node refused the request's content, for example a transaction that failed
    /// verification. Maps to `INVALID_ARGUMENT`.
    #[error("{0}")]
    Rejected(String),
    /// The backend answered with something it should not have. Maps to `INTERNAL`.
    #[error("{0}")]
    Unexpected(String),
}

impl From<BackendError> for Status {
    fn from(error: BackendError) -> Self {
        match error {
            BackendError::Unavailable(message) => Self::unavailable(message),
            BackendError::Rejected(message) => Self::invalid_argument(message),
            BackendError::Unexpected(message) => Self::internal(message),
        }
    }
}

/// A transaction in the best chain: its serialized bytes and the height it was mined at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MinedTransaction {
    /// The transaction, serialized.
    pub bytes: Vec<u8>,
    /// The height of the block that holds it.
    pub height: u32,
}

/// The three commitment trees at one block, each as the hex string the light wallet protocol
/// carries. An empty string means the pool was not active at that block.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TreeStateHex {
    /// Sapling tree, `zcash_serialize`d frontier as hex.
    pub sapling: String,
    /// Orchard tree, same encoding.
    pub orchard: String,
    /// Ironwood tree, same encoding.
    pub ironwood: String,
}

/// One completed note commitment subtree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubtreeRoot {
    /// The subtree root, 32 bytes in the pool's byte order.
    pub root: Vec<u8>,
    /// The height of the block whose last commitment completed the subtree.
    pub end_height: u32,
}

/// One unspent transparent output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressUtxo {
    /// The address, encoded for the network.
    pub address: String,
    /// The transaction that created the output.
    pub txid: [u8; 32],
    /// The output's index in that transaction.
    pub index: u32,
    /// The output's lock script.
    pub script: Vec<u8>,
    /// The output's value in zatoshis.
    pub value: u64,
    /// The height the transaction was mined at.
    pub height: u32,
}

/// A shielded pool with a note commitment tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShieldedPool {
    /// Sapling.
    Sapling,
    /// Orchard.
    Orchard,
    /// Ironwood.
    Ironwood,
}

/// Wakes when the best chain tip changes. Streams that must restart at a new tip, such as the
/// mempool stream, wait on this.
#[tonic::async_trait]
pub trait TipListener: Send {
    /// Resolves once the tip has changed since the listener was created or last resolved.
    async fn tip_changed(&mut self) -> Result<(), BackendError>;
}

/// Chain state and node access for the service, behind one interface.
///
/// Every method is a point-in-time read; none of them hold a lock across the call. Methods that
/// need the mempool fail with [`BackendError::Unavailable`] on a backend that has no mempool
/// access.
#[tonic::async_trait]
pub trait StateBackend: Send + Sync + 'static {
    /// The network the node runs on.
    fn network(&self) -> Network;

    /// The node's best chain tip height, or `None` on an empty chain.
    async fn tip_height(&self) -> Result<Option<u32>, BackendError>;

    /// A full block from the best chain by hash. `None` when the block is not in the best chain.
    async fn block(&self, hash: block::Hash) -> Result<Option<Arc<Block>>, BackendError>;

    /// A mined transaction by id. `None` when it is not in the best chain.
    async fn transaction(
        &self,
        hash: transaction::Hash,
    ) -> Result<Option<MinedTransaction>, BackendError>;

    /// The commitment trees at the block with this hash.
    async fn tree_state(&self, hash: block::Hash) -> Result<TreeStateHex, BackendError>;

    /// Completed subtrees of one pool, from `start` on, at most `limit` of them.
    async fn subtree_roots(
        &self,
        pool: ShieldedPool,
        start: NoteCommitmentSubtreeIndex,
        limit: Option<NoteCommitmentSubtreeIndex>,
    ) -> Result<Vec<SubtreeRoot>, BackendError>;

    /// Ids of the transactions that touch `address` within the height range, in chain order.
    async fn address_transaction_ids(
        &self,
        address: transparent::Address,
        heights: RangeInclusive<u32>,
    ) -> Result<Vec<transaction::Hash>, BackendError>;

    /// The summed balance of the addresses, in zatoshis.
    async fn address_balance(
        &self,
        addresses: HashSet<transparent::Address>,
    ) -> Result<u64, BackendError>;

    /// Every unspent output of the addresses, in chain order.
    async fn address_utxos(
        &self,
        addresses: HashSet<transparent::Address>,
    ) -> Result<Vec<AddressUtxo>, BackendError>;

    /// Every transaction in the node's mempool.
    async fn mempool_transactions(&self) -> Result<Vec<UnminedTx>, BackendError>;

    /// Verifies and queues a transaction. Returns its id.
    async fn submit_transaction(
        &self,
        transaction: Transaction,
    ) -> Result<transaction::Hash, BackendError>;

    /// A new listener for best tip changes, starting from the tip as of now.
    fn tip_listener(&self) -> Result<Box<dyn TipListener>, BackendError>;
}

/// The embedded Zakura node, reached in-process.
///
/// Built from a `ReadStateService` alone it serves chain reads and fails mempool requests;
/// built from a [`NodeClient`] it serves everything.
#[derive(Clone)]
pub struct InProcessBackend {
    read: ReadStateService,
    node: Option<NodeClient>,
}

impl std::fmt::Debug for InProcessBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InProcessBackend")
            .field("node", &self.node.is_some())
            .finish_non_exhaustive()
    }
}

impl InProcessBackend {
    /// Chain reads only. Mempool requests fail with [`BackendError::Unavailable`].
    pub const fn new(read: ReadStateService) -> Self {
        Self { read, node: None }
    }

    /// Chain reads and mempool access through the node's handles.
    pub fn with_node(node: NodeClient) -> Self {
        Self { read: node.read_state(), node: Some(node) }
    }

    fn node(&self) -> Result<&NodeClient, BackendError> {
        self.node.as_ref().ok_or_else(|| {
            BackendError::Unavailable("embedded Zakura node handle is unavailable".into())
        })
    }

    async fn read(&self, request: ReadRequest) -> Result<ReadResponse, BackendError> {
        self.read
            .clone()
            .oneshot(request)
            .await
            .map_err(|error| BackendError::Unavailable(format!("Zakura read failed: {error}")))
    }
}

fn unexpected(what: &str) -> BackendError {
    BackendError::Unexpected(format!("unexpected {what} response"))
}

/// Zakura's mempool futures are not `Send`, so they run on a blocking thread with their own
/// `block_on`.
async fn block_on_node<T, E, F>(call: F) -> Result<T, BackendError>
where
    F: FnOnce() -> Result<T, E> + Send + 'static,
    T: Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    tokio::task::spawn_blocking(call)
        .await
        .map_err(|error| BackendError::Unavailable(format!("Zakura task failed: {error}")))?
        .map_err(|error| BackendError::Unavailable(error.to_string()))
}

#[tonic::async_trait]
impl StateBackend for InProcessBackend {
    fn network(&self) -> Network {
        self.read.db().network()
    }

    async fn tip_height(&self) -> Result<Option<u32>, BackendError> {
        match self.read(ReadRequest::Tip).await? {
            ReadResponse::Tip(tip) => Ok(tip.map(|(height, _)| height.0)),
            _ => Err(unexpected("tip")),
        }
    }

    async fn block(&self, hash: block::Hash) -> Result<Option<Arc<Block>>, BackendError> {
        match self.read(ReadRequest::Block(hash.into())).await? {
            ReadResponse::Block(block) => Ok(block),
            _ => Err(unexpected("block")),
        }
    }

    async fn transaction(
        &self,
        hash: transaction::Hash,
    ) -> Result<Option<MinedTransaction>, BackendError> {
        match self.read(ReadRequest::Transaction(hash)).await? {
            ReadResponse::Transaction(Some(mined)) => Ok(Some(MinedTransaction {
                bytes: mined
                    .tx
                    .zcash_serialize_to_vec()
                    .map_err(|error| BackendError::Unexpected(error.to_string()))?,
                height: mined.height.0,
            })),
            ReadResponse::Transaction(None) => Ok(None),
            _ => Err(unexpected("transaction")),
        }
    }

    async fn tree_state(&self, hash: block::Hash) -> Result<TreeStateHex, BackendError> {
        let (sapling, orchard, ironwood) = tokio::try_join!(
            self.read(ReadRequest::SaplingTree(hash.into())),
            self.read(ReadRequest::OrchardTree(hash.into())),
            self.read(ReadRequest::IronwoodTree(hash.into())),
        )?;
        let sapling = match sapling {
            ReadResponse::SaplingTree(tree) => {
                tree.map(|tree| hex::encode(tree.to_rpc_bytes())).unwrap_or_default()
            }
            _ => return Err(unexpected("Sapling tree")),
        };
        let orchard = match orchard {
            ReadResponse::OrchardTree(tree) => {
                tree.map(|tree| hex::encode(tree.to_rpc_bytes())).unwrap_or_default()
            }
            _ => return Err(unexpected("Orchard tree")),
        };
        let ironwood = match ironwood {
            ReadResponse::IronwoodTree(tree) => {
                tree.map(|tree| hex::encode(tree.to_rpc_bytes())).unwrap_or_default()
            }
            _ => return Err(unexpected("Ironwood tree")),
        };
        Ok(TreeStateHex { sapling, orchard, ironwood })
    }

    async fn subtree_roots(
        &self,
        pool: ShieldedPool,
        start_index: NoteCommitmentSubtreeIndex,
        limit: Option<NoteCommitmentSubtreeIndex>,
    ) -> Result<Vec<SubtreeRoot>, BackendError> {
        let request = match pool {
            ShieldedPool::Sapling => ReadRequest::SaplingSubtrees { start_index, limit },
            ShieldedPool::Orchard => ReadRequest::OrchardSubtrees { start_index, limit },
            ShieldedPool::Ironwood => ReadRequest::IronwoodSubtrees { start_index, limit },
        };
        let roots = match self.read(request).await? {
            ReadResponse::SaplingSubtrees(subtrees) => subtrees
                .into_values()
                .map(|subtree| SubtreeRoot {
                    root: subtree.root.to_bytes().to_vec(),
                    end_height: subtree.end_height.0,
                })
                .collect(),
            ReadResponse::OrchardSubtrees(subtrees) => subtrees
                .into_values()
                .map(|subtree| SubtreeRoot {
                    root: subtree.root.to_repr().to_vec(),
                    end_height: subtree.end_height.0,
                })
                .collect(),
            ReadResponse::IronwoodSubtrees(subtrees) => subtrees
                .into_values()
                .map(|subtree| SubtreeRoot {
                    root: subtree.root.to_repr().to_vec(),
                    end_height: subtree.end_height.0,
                })
                .collect(),
            _ => return Err(unexpected("subtree")),
        };
        Ok(roots)
    }

    async fn address_transaction_ids(
        &self,
        address: transparent::Address,
        heights: RangeInclusive<u32>,
    ) -> Result<Vec<transaction::Hash>, BackendError> {
        let request = ReadRequest::TransactionIdsByAddresses {
            addresses: HashSet::from([address]),
            height_range: block::Height(*heights.start())..=block::Height(*heights.end()),
        };
        match self.read(request).await? {
            ReadResponse::AddressesTransactionIds(ids) => Ok(ids.into_values().collect()),
            _ => Err(unexpected("address transaction")),
        }
    }

    async fn address_balance(
        &self,
        addresses: HashSet<transparent::Address>,
    ) -> Result<u64, BackendError> {
        match self.read(ReadRequest::AddressBalance(addresses)).await? {
            ReadResponse::AddressBalance { balance, .. } => Ok(u64::from(balance)),
            _ => Err(unexpected("address balance")),
        }
    }

    async fn address_utxos(
        &self,
        addresses: HashSet<transparent::Address>,
    ) -> Result<Vec<AddressUtxo>, BackendError> {
        match self.read(ReadRequest::UtxosByAddresses(addresses)).await? {
            ReadResponse::AddressUtxos(utxos) => Ok(utxos
                .utxos()
                .map(|(address, txid, location, output)| AddressUtxo {
                    address: address.to_string(),
                    txid: txid.0,
                    index: location.output_index().index(),
                    script: output.lock_script.as_raw_bytes().to_vec(),
                    value: u64::from(output.value),
                    height: location.height().0,
                })
                .collect()),
            _ => Err(unexpected("address UTXO")),
        }
    }

    async fn mempool_transactions(&self) -> Result<Vec<UnminedTx>, BackendError> {
        let node = self.node()?.clone();
        let runtime = tokio::runtime::Handle::current();
        block_on_node(move || {
            runtime
                .block_on(node.mempool_transactions())
                .map_err(|error| format!("Zakura mempool query failed: {error}"))
        })
        .await
    }

    async fn submit_transaction(
        &self,
        transaction: Transaction,
    ) -> Result<transaction::Hash, BackendError> {
        let node = self.node()?.clone();
        let runtime = tokio::runtime::Handle::current();
        let submitted = tokio::task::spawn_blocking(move || {
            runtime
                .block_on(node.submit_transaction(transaction))
                .map_err(|error| error.to_string())
        })
        .await
        .map_err(|error| BackendError::Unavailable(format!("Zakura task failed: {error}")))?;
        submitted.map(|id| id.mined_id()).map_err(|error| {
            BackendError::Rejected(format!("Zakura rejected transaction: {error}"))
        })
    }

    fn tip_listener(&self) -> Result<Box<dyn TipListener>, BackendError> {
        let mut changes = self.node()?.subscribe_chain_tip();
        let _ = changes.last_tip_change();
        Ok(Box::new(InProcessTipListener(changes)))
    }
}

struct InProcessTipListener(ChainTipChange);

#[tonic::async_trait]
impl TipListener for InProcessTipListener {
    async fn tip_changed(&mut self) -> Result<(), BackendError> {
        self.0.wait_for_tip_change().await.map(|_| ()).map_err(|error| {
            BackendError::Unavailable(format!("Zakura chain-tip listener failed: {error}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_map_to_one_status_code_each() {
        assert_eq!(
            Status::from(BackendError::Unavailable("a".into())).code(),
            tonic::Code::Unavailable
        );
        assert_eq!(
            Status::from(BackendError::Rejected("b".into())).code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            Status::from(BackendError::Unexpected("c".into())).code(),
            tonic::Code::Internal
        );
        assert_eq!(Status::from(BackendError::Rejected("b".into())).message(), "b");
    }

    #[test]
    fn read_only_backend_has_no_mempool() {
        tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
            let (_state, read, _tip, _change) = zakura_state::init(
                zakura_state::Config::ephemeral(),
                &Network::Mainnet,
                block::Height::MAX,
                0,
            )
            .await
            .expect("ephemeral state initializes");
            let backend = InProcessBackend::new(read);
            assert_eq!(backend.network(), Network::Mainnet);
            assert_eq!(backend.tip_height().await.unwrap(), None);
            let error = backend.mempool_transactions().await.unwrap_err();
            assert_eq!(
                error,
                BackendError::Unavailable("embedded Zakura node handle is unavailable".into())
            );
            assert!(backend.tip_listener().is_err());
        });
    }
}
