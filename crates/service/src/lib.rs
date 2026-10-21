//! Shared CompactTxStreamer behavior with gRPC and Zakura p2p transport adapters.

// Public items are not fully documented yet. Remove this once every `pub` item has a doc comment.
#![allow(missing_docs)]

pub mod grpc;
pub mod p2p;
mod serve;
mod service;

pub use service::{
    CompactService, HeadFollowerConfig, HeadFollowerError, Readiness, ServingSnapshot,
    SnapshotError,
};

mod telemetry;
