#![allow(missing_docs)]

mod support;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::{sync::Arc, time::Duration};
use support::{
    Client, GET_BLOCK_RANGE, GET_BLOCK_RANGE_NULLIFIERS, LocalServer, RawClient, consume,
    consume_raw, range,
};
use tokio::{sync::Barrier, task::JoinSet};
use ztreamer_protocol::proto;

fn grpc(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let server = runtime.block_on(LocalServer::start());
    let clients = runtime.block_on(async {
        let mut clients = Vec::new();
        // Each simulated wallet owns a connection; cloning a Tonic client shares it.
        for _ in 0..32 {
            clients.push(Client::connect(server.endpoint.clone()).await.unwrap());
        }
        clients
    });
    let raw_clients = runtime.block_on(async {
        let mut clients = Vec::new();
        for _ in 0..32 {
            clients.push(RawClient::connect(server.endpoint.clone()).await.unwrap());
        }
        clients
    });
    // Same requests without client-side decoding, which otherwise dominates the profile.
    let mut group = c.benchmark_group("grpc_raw_mixed_v1");
    for concurrency in [1, 8, 32] {
        group.throughput(Throughput::Elements(2_000 * concurrency as u64));
        group.bench_with_input(
            BenchmarkId::new("2000-blocks", concurrency),
            &concurrency,
            |b, &concurrency| {
                b.to_async(&runtime).iter(|| async {
                    let barrier = Arc::new(Barrier::new(concurrency));
                    let mut tasks = JoinSet::new();
                    for mut client in raw_clients[..concurrency].iter().cloned() {
                        let barrier = barrier.clone();
                        tasks.spawn(async move {
                            barrier.wait().await;
                            tokio::time::timeout(
                                Duration::from_secs(30),
                                consume_raw(
                                    &mut client,
                                    GET_BLOCK_RANGE,
                                    range(0, 1_999),
                                    Duration::ZERO,
                                ),
                            )
                            .await
                            .unwrap()
                            .unwrap()
                        });
                    }
                    while let Some(result) = tasks.join_next().await {
                        std::hint::black_box(result.unwrap());
                    }
                });
            },
        );
    }
    group.finish();

    // Requests that project each stored block before sending it.
    let mut group = c.benchmark_group("grpc_raw_projected_mixed_v1");
    let mut orchard = range(0, 1_999);
    orchard.pool_types = vec![proto::PoolType::Orchard as i32];
    for (name, method, request) in [
        ("nullifiers", GET_BLOCK_RANGE_NULLIFIERS, range(0, 1_999)),
        ("orchard-only", GET_BLOCK_RANGE, orchard),
    ] {
        for concurrency in [1, 8] {
            group.throughput(Throughput::Elements(2_000 * concurrency as u64));
            group.bench_with_input(
                BenchmarkId::new(name, concurrency),
                &concurrency,
                |b, &concurrency| {
                    b.to_async(&runtime).iter(|| async {
                        let barrier = Arc::new(Barrier::new(concurrency));
                        let mut tasks = JoinSet::new();
                        for mut client in raw_clients[..concurrency].iter().cloned() {
                            let barrier = barrier.clone();
                            let request = request.clone();
                            tasks.spawn(async move {
                                barrier.wait().await;
                                tokio::time::timeout(
                                    Duration::from_secs(30),
                                    consume_raw(&mut client, method, request, Duration::ZERO),
                                )
                                .await
                                .unwrap()
                                .unwrap()
                            });
                        }
                        while let Some(result) = tasks.join_next().await {
                            std::hint::black_box(result.unwrap());
                        }
                    });
                },
            );
        }
    }
    group.finish();
    drop(raw_clients);
    for (name, delay) in [
        ("grpc_mixed_v1", Duration::ZERO),
        ("grpc_slow_mixed_v1", Duration::from_millis(1)),
    ] {
        let mut group = c.benchmark_group(name);
        for concurrency in [1, 8, 16, 32] {
            group.throughput(Throughput::Elements(2_000 * concurrency as u64));
            group.bench_with_input(
                BenchmarkId::new("2000-blocks", concurrency),
                &concurrency,
                |b, &concurrency| {
                    b.to_async(&runtime).iter(|| async {
                        let barrier = Arc::new(Barrier::new(concurrency));
                        let mut tasks = JoinSet::new();
                        for mut client in clients[..concurrency].iter().cloned() {
                            let barrier = barrier.clone();
                            tasks.spawn(async move {
                                barrier.wait().await;
                                tokio::time::timeout(
                                    Duration::from_secs(30),
                                    consume(&mut client, range(0, 1_999), delay),
                                )
                                .await
                                .unwrap()
                                .unwrap()
                            });
                        }
                        while let Some(result) = tasks.join_next().await {
                            std::hint::black_box(result.unwrap());
                        }
                    });
                },
            );
        }
        group.finish();
    }
    drop(clients);
    runtime.block_on(server.stop());
}

criterion_group! { name = benches; config = Criterion::default().noise_threshold(0.05).sample_size(20); targets = grpc }
criterion_main!(benches);
