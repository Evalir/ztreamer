//! Transparent address requests: transaction lookups, balances, and UTXOs.

use std::collections::HashSet;

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;
use zakura_chain::transparent;
use ztreamer_protocol::proto;

use super::{CompactService, RpcStream};

const MAX_UTXO_ADDRESSES: usize = 1_000;
impl CompactService {
    pub(crate) async fn taddress_transactions(
        &self,
        request: proto::TransparentAddressBlockFilter,
    ) -> Result<RpcStream<proto::RawTransaction>, Status> {
        let address = self.parse_address(&request.address)?;
        let range =
            request.range.ok_or_else(|| Status::invalid_argument("block range is required"))?;
        let tip = self.zakura_tip().await?;
        let endpoint = |endpoint: Option<proto::BlockId>| -> Result<Option<u32>, Status> {
            endpoint
                .map(|block| {
                    u32::try_from(block.height)
                        .map(|height| height.min(tip))
                        .map_err(|_| Status::invalid_argument("block height exceeds u32"))
                })
                .transpose()
        };
        let mut start = endpoint(range.start)?.unwrap_or(0);
        let mut end = endpoint(range.end)?.unwrap_or(tip);
        if end == 0 {
            end = tip;
        }
        if start > end {
            std::mem::swap(&mut start, &mut end);
        }
        let transactions = self.backend.address_transaction_ids(address, start..=end).await?;

        let service = self.clone();
        let (sender, receiver) = mpsc::channel(1);
        tokio::spawn(async move {
            for hash in transactions {
                match service.mined_transaction(hash).await {
                    Ok(Some(transaction)) => {
                        if sender.send(Ok(transaction)).await.is_err() {
                            return;
                        }
                    }
                    Ok(None) => {
                        let _ = sender
                            .send(Err(Status::unavailable(
                                "Zakura address index referenced a missing transaction",
                            )))
                            .await;
                        return;
                    }
                    Err(error) => {
                        let _ = sender.send(Err(error)).await;
                        return;
                    }
                }
            }
        });
        Ok(Box::pin(ReceiverStream::new(receiver)))
    }

    pub(crate) async fn taddress_balance(
        &self,
        addresses: Vec<String>,
    ) -> Result<proto::Balance, Status> {
        self.taddress_balance_parsed(self.parse_addresses(addresses)?).await
    }

    pub(crate) async fn taddress_balance_parsed(
        &self,
        addresses: HashSet<transparent::Address>,
    ) -> Result<proto::Balance, Status> {
        let balance = self.backend.address_balance(addresses).await?;
        Ok(proto::Balance {
            value_zat: i64::try_from(balance)
                .map_err(|_| Status::out_of_range("transparent balance exceeds i64"))?,
        })
    }

    pub(crate) async fn address_utxos(
        &self,
        request: proto::GetAddressUtxosArg,
    ) -> Result<Vec<proto::GetAddressUtxosReply>, Status> {
        if request.addresses.len() > MAX_UTXO_ADDRESSES {
            return Err(Status::invalid_argument(format!(
                "too many addresses: {} exceeds {MAX_UTXO_ADDRESSES}",
                request.addresses.len()
            )));
        }
        let addresses = self.parse_addresses(request.addresses)?;
        let utxos = self.backend.address_utxos(addresses).await?;
        let limit = usize::try_from(request.max_entries).unwrap_or(usize::MAX);
        utxos
            .into_iter()
            .filter(|utxo| u64::from(utxo.height) >= request.start_height)
            .take(if limit == 0 { usize::MAX } else { limit })
            .map(|utxo| {
                Ok(proto::GetAddressUtxosReply {
                    address: utxo.address,
                    txid: utxo.txid.to_vec(),
                    index: i32::try_from(utxo.index).map_err(|_| {
                        Status::out_of_range("transparent output index exceeds i32")
                    })?,
                    script: utxo.script,
                    value_zat: i64::try_from(utxo.value).map_err(|_| {
                        Status::out_of_range("transparent output value exceeds i64")
                    })?,
                    height: u64::from(utxo.height),
                })
            })
            .collect()
    }

    fn parse_addresses(
        &self,
        addresses: impl IntoIterator<Item = String>,
    ) -> Result<HashSet<transparent::Address>, Status> {
        addresses.into_iter().map(|address| self.parse_address(&address)).collect()
    }

    pub(crate) fn parse_address(&self, address: &str) -> Result<transparent::Address, Status> {
        let address: transparent::Address = address
            .parse()
            .map_err(|error| Status::invalid_argument(format!("invalid address: {error}")))?;
        Ok(address)
    }

    async fn zakura_tip(&self) -> Result<u32, Status> {
        self.backend.tip_height().await?.ok_or_else(|| Status::unavailable("Zakura chain is empty"))
    }
}
