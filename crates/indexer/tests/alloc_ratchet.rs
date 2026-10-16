//! Allocation-count ratchet for codec and index read hot paths.
//!
//! Allocation counts are deterministic, unlike wall-clock benchmarks, so CI can hold
//! the line on every pull request. A count above its ceiling fails; a count below it
//! also fails, asking for the ceiling to be lowered so later regressions are caught.

#[path = "../../../benchmarks/fixtures.rs"]
mod fixtures;

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

use ztreamer_indexer::{
    codec::{CompactBlockRecord, EncodedBlockRecord, decode_range_record, encode_range},
    index::{Index, RANGE_SIZE},
};

struct Counting;

thread_local! {
    // Per thread, so tests running in parallel do not count each other.
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn allocations<T>(run: impl FnOnce() -> T) -> u64 {
    let before = ALLOCATIONS.with(Cell::get);
    let output = run();
    let count = ALLOCATIONS.with(Cell::get) - before;
    drop(output);
    count
}

/// `ALLOC_RATCHET_REPORT=1 cargo test --test alloc_ratchet -- --nocapture` prints every count.
fn ratchet(name: &str, actual: u64, ceiling: u64) {
    if std::env::var_os("ALLOC_RATCHET_REPORT").is_some() {
        eprintln!("{name}: {actual} (ceiling {ceiling})");
        return;
    }
    assert!(
        actual <= ceiling,
        "{name}: {actual} allocations exceeds the ratchet ceiling of {ceiling}"
    );
    assert!(
        actual == ceiling,
        "{name}: {actual} allocations is below the ceiling of {ceiling}; lower it to {actual}"
    );
}

#[test]
fn codec_allocations() {
    let heavy = fixtures::mixed_records(10).pop().unwrap();
    let encoded = heavy.encode().unwrap();
    let range = fixtures::mixed_records(RANGE_SIZE);
    let encoded_range = encode_range(&range).unwrap();

    ratchet(
        "encode mixed-heavy block",
        allocations(|| heavy.encode().unwrap()),
        1,
    );
    ratchet(
        "decode mixed-heavy block",
        allocations(|| CompactBlockRecord::decode(&encoded).unwrap()),
        329,
    );
    ratchet(
        "encode 1000-block mixed range",
        allocations(|| encode_range(&range).unwrap()),
        11,
    );
    ratchet(
        "decode mixed-heavy record from a range",
        allocations(|| decode_range_record(&encoded_range, 999).unwrap()),
        329,
    );
}

#[test]
fn index_read_allocations() {
    let dir = tempfile::tempdir().unwrap();
    let index = Index::open(dir.path(), 512 * 1024 * 1024, "Mainnet", [9; 32]).unwrap();
    let records = fixtures::mixed_records(2_200);
    fixtures::populate(&index, &records, Some(1_999));

    for (name, start, end, ceiling) in [
        ("sealed 64-block encoded read", 100, 163, 65),
        ("mutable 64-block encoded read", 2_000, 2_063, 128),
    ] {
        let mut blocks = Vec::with_capacity(64);
        let count = allocations(|| {
            index
                .read_range_latest_as(start, end, |record: EncodedBlockRecord| {
                    blocks.push(record);
                    true
                })
                .unwrap()
        });
        assert_eq!(blocks.len(), 64);
        ratchet(name, count, ceiling);
    }
}
