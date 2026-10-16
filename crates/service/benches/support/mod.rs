#![allow(dead_code)]

use prost::Message as _;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};
use zakura_chain::{block, parameters::Network};
use zakura_state::Config;
use ztreamer_indexer::index::Index;
use ztreamer_protocol::proto::{self, compact_tx_streamer_client::CompactTxStreamerClient};
use ztreamer_protocol::wire::compact_tx_streamer_server::CompactTxStreamerServer;
use ztreamer_service::CompactService;

#[path = "../../../../benchmarks/fixtures.rs"]
pub mod fixtures;

pub type Client = CompactTxStreamerClient<Channel>;

/// A wallet connection that keeps each `CompactBlock` as its received frame.
#[derive(Clone)]
pub struct RawClient(tonic::client::Grpc<Channel>);

impl RawClient {
    pub async fn connect(endpoint: String) -> Result<Self, Error> {
        let channel = Channel::from_shared(endpoint)?.connect().await?;
        Ok(Self(tonic::client::Grpc::new(channel)))
    }
}

/// Encodes requests with Prost and passes response frames through undecoded.
#[derive(Clone, Copy, Default)]
struct RawCodec;

impl tonic::codec::Codec for RawCodec {
    type Encode = proto::BlockRange;
    type Decode = prost::bytes::Bytes;
    type Encoder = RawCodec;
    type Decoder = RawCodec;

    fn encoder(&mut self) -> Self::Encoder {
        *self
    }

    fn decoder(&mut self) -> Self::Decoder {
        *self
    }
}

impl tonic::codec::Encoder for RawCodec {
    type Item = proto::BlockRange;
    type Error = tonic::Status;

    fn encode(
        &mut self,
        item: Self::Item,
        dst: &mut tonic::codec::EncodeBuf<'_>,
    ) -> Result<(), Self::Error> {
        item.encode(dst)
            .map_err(|error| tonic::Status::internal(error.to_string()))
    }
}

impl tonic::codec::Decoder for RawCodec {
    type Item = prost::bytes::Bytes;
    type Error = tonic::Status;

    fn decode(
        &mut self,
        src: &mut tonic::codec::DecodeBuf<'_>,
    ) -> Result<Option<Self::Item>, Self::Error> {
        use prost::bytes::Buf as _;
        Ok(Some(src.copy_to_bytes(src.remaining())))
    }
}

/// `CompactBlock.height` is field 2 and is encoded first; proto3 omits height 0.
fn raw_height(mut block: &[u8]) -> Result<u64, Error> {
    if block.first() != Some(&0x10) {
        return Ok(0);
    }
    block = &block[1..];
    Ok(prost::encoding::decode_varint(&mut block)?)
}
pub type Error = Box<dyn std::error::Error + Send + Sync>;

pub struct Fixture {
    pub service: CompactService,
    // Keep the index directory alive until the service has stopped.
    _dir: tempfile::TempDir,
}

impl Fixture {
    pub async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let index =
            Arc::new(Index::open(dir.path(), 512 * 1024 * 1024, "Mainnet", [9; 32]).unwrap());
        let records = fixtures::mixed_records(2_210);
        let state = fixtures::populate(&index, &records[..2_200], Some(1_999));
        let (_state, read, _tip, _change) = zakura_state::init(
            Config::ephemeral(),
            &Network::Mainnet,
            block::Height::MAX,
            0,
        )
        .await
        .unwrap();
        let service = CompactService::new(index, state, "main", read);
        service
            .publish_head(state, records[2_200..].to_vec())
            .unwrap();
        Self { service, _dir: dir }
    }
}

pub struct LocalServer {
    pub endpoint: String,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<Result<(), tonic::transport::Error>>,
    _fixture: Fixture,
}

impl LocalServer {
    pub async fn start() -> Self {
        let fixture = Fixture::new().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown, stopped) = oneshot::channel();
        let service = fixture.service.clone();
        let task = tokio::spawn(async move {
            Server::builder()
                .add_service(CompactTxStreamerServer::new(service))
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                    let _ = stopped.await;
                })
                .await
        });
        Self {
            endpoint,
            shutdown,
            task,
            _fixture: fixture,
        }
    }

    pub async fn stop(self) {
        let _ = self.shutdown.send(());
        tokio::time::timeout(Duration::from_secs(10), self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

pub fn range(start: u32, end: u32) -> proto::BlockRange {
    let id = |height| {
        Some(proto::BlockId {
            height: u64::from(height),
            hash: Vec::new(),
        })
    };
    proto::BlockRange {
        start: id(start),
        end: id(end),
        pool_types: Vec::new(),
    }
}

/// Like [`consume`], but leaves blocks encoded so the measurement is dominated by the server.
pub async fn consume_raw(
    client: &mut RawClient,
    range: proto::BlockRange,
    delay: Duration,
) -> Result<Observation, Error> {
    let start = range.start.as_ref().unwrap().height;
    let end = range.end.as_ref().unwrap().height;
    let expected = start.abs_diff(end) + 1;
    let started = Instant::now();
    client.0.ready().await?;
    let path = tonic::codegen::http::uri::PathAndQuery::from_static(
        "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetBlockRange",
    );
    let mut stream = client
        .0
        .server_streaming(tonic::Request::new(range), path, RawCodec)
        .await?
        .into_inner();
    let mut first = None;
    let mut blocks = 0;
    let mut bytes = 0;
    while let Some(block) = stream.message().await? {
        first.get_or_insert_with(|| started.elapsed());
        let height = if start <= end {
            start.checked_add(blocks)
        } else {
            start.checked_sub(blocks)
        };
        if blocks >= expected || Some(raw_height(&block)?) != height {
            return Err("range returned an unexpected height".into());
        }
        blocks += 1;
        bytes += block.len() as u64;
        std::hint::black_box(block);
        if !delay.is_zero() && blocks % 64 == 0 && blocks < expected {
            tokio::time::sleep(delay).await;
        }
    }
    if blocks != expected {
        return Err("range ended before all blocks arrived".into());
    }
    Ok(Observation {
        first: first.unwrap(),
        complete: started.elapsed(),
        bytes,
        blocks,
    })
}

pub struct Observation {
    pub first: Duration,
    pub complete: Duration,
    pub bytes: u64,
    pub blocks: u64,
}

/// Measures request-to-first-message and request-to-EOF, including decoding and
/// consumer delay. Validates complete, ordered delivery for synthetic or live data.
pub async fn consume(
    client: &mut Client,
    range: proto::BlockRange,
    delay: Duration,
) -> Result<Observation, Error> {
    let start = range.start.as_ref().unwrap().height;
    let end = range.end.as_ref().unwrap().height;
    let expected = start.abs_diff(end) + 1;
    let started = Instant::now();
    let mut stream = client.get_block_range(range).await?.into_inner();
    let mut first = None;
    let mut blocks = 0;
    let mut bytes = 0;
    while let Some(block) = stream.message().await? {
        first.get_or_insert_with(|| started.elapsed());
        let height = if start <= end {
            start.checked_add(blocks)
        } else {
            start.checked_sub(blocks)
        };
        if blocks >= expected || Some(block.height) != height {
            return Err("range returned an unexpected height".into());
        }
        blocks += 1;
        bytes += block.encoded_len() as u64;
        std::hint::black_box(block);
        if !delay.is_zero() && blocks % 64 == 0 && blocks < expected {
            tokio::time::sleep(delay).await;
        }
    }
    if blocks != expected {
        return Err("range ended before all blocks arrived".into());
    }
    Ok(Observation {
        first: first.unwrap(),
        complete: started.elapsed(),
        bytes,
        blocks,
    })
}
