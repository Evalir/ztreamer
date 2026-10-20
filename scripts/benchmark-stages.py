#!/usr/bin/env python3
"""Shows the times of a `benchmark-snapshot.sh` run for each band of heights.

Usage: benchmark-stages.py RUN_DIR [--band BLOCKS]

The script reads RUN_DIR/metrics.csv, which has one Prometheus scrape each
second. On Linux, it also reads RUN_DIR/processstats.csv. For each band of
committed heights, it shows the wall time, the blocks per second, the process
I/O, and the CPU time. It also shows where the pipeline used its time:

- The sum of the fetch worker stages, for all workers.
- The encode time and the batch send wait of the coordinator.
- The time of each writer stage.

If the writer seconds are near the wall time of the band, the single writer
limits the speed. If the fetch read seconds are near `workers x wall` and the
writer time is low, the reads limit the speed.
"""

import argparse
import csv
import re
from bisect import bisect_left
from collections import defaultdict
from pathlib import Path

HEIGHT = "ztreamer_index_durable_block_height"
CLOCK_TICKS = 100  # Linux USER_HZ for /proc/<pid>/stat utime and stime.

# (column, metric name, label value or None). For a histogram, use its `_sum` series.
SERIES = [
    ("tx_read", "ztreamer_pipeline_stage_seconds_sum", ("stage", "transaction_read")),
    ("header_read", "ztreamer_pipeline_stage_seconds_sum", ("stage", "header_read")),
    ("txid_read", "ztreamer_pipeline_stage_seconds_sum", ("stage", "txid_read")),
    ("parse", "ztreamer_pipeline_stage_seconds_sum", ("stage", "parse")),
    ("worker_wait", "ztreamer_pipeline_stage_seconds_sum", ("stage", "worker_send_wait")),
    ("encode", "ztreamer_pipeline_encode_seconds_sum", None),
    ("coord_wait", "ztreamer_pipeline_batch_send_wait_seconds_sum", None),
    ("write", "ztreamer_pipeline_commit_seconds_sum", ("outcome", "success")),
    ("hash_index", "ztreamer_index_write_seconds_sum", ("stage", "hash_index")),
    ("seal_read", "ztreamer_index_write_seconds_sum", ("stage", "seal_read")),
    ("seal_encode", "ztreamer_index_write_seconds_sum", ("stage", "seal_encode")),
    ("seal_put", "ztreamer_index_write_seconds_sum", ("stage", "seal_put")),
    ("mut_put", "ztreamer_index_write_seconds_sum", ("stage", "mutable_put")),
    ("state_put", "ztreamer_index_write_seconds_sum", ("stage", "state_put")),
    ("commit", "ztreamer_index_write_seconds_sum", ("stage", "commit")),
    ("source_MB", "ztreamer_pipeline_source_bytes", None),
    ("seal_rd_blk", "ztreamer_index_write_seal_read_blocks", None),
]

LINE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*?)(?:_total)?(?:\{(.*)\})?$')
LABEL = re.compile(r'(\w+)="([^"]*)"')


def complete_rows(path):
    """Reads the CSV rows of `path`. A last line with no newline is incomplete, so it is skipped.

    The benchmark writes these files while it runs, and a stop can cut the last line.
    """
    text = path.read_text()
    if not text.endswith("\n"):
        text = text[: text.rfind("\n") + 1]
    return list(csv.DictReader(text.splitlines()))


def load_metrics(path):
    """Returns (times, {series: [values at those times]}). A missing value is the last value."""
    samples = defaultdict(dict)
    for row in complete_rows(path):
        if None in (row.get("unix_time"), row.get("metric"), row.get("value")):
            continue
        match = LINE.match(row["metric"])
        if not match:
            continue
        name, labels = match.group(1), dict(LABEL.findall(match.group(2) or ""))
        try:
            value = float(row["value"])
            time = float(row["unix_time"])
        except ValueError:
            continue
        if name == HEIGHT:
            samples["height"][time] = value
        for column, metric, label in SERIES:
            if name == metric and (label is None or labels.get(label[0]) == label[1]):
                samples[column][time] = samples[column].get(time, 0.0) + value
    times = sorted(samples["height"])
    series = {}
    for column in ["height"] + [column for column, _, _ in SERIES]:
        last, values = 0.0, []
        for time in times:
            last = samples[column].get(time, last)
            values.append(last)
        series[column] = values
    return times, series


def load_process(path):
    if not path.exists():
        return None
    rows = complete_rows(path)
    if not rows or "read_bytes" not in rows[0]:
        return None  # The macOS samples have no I/O counters.
    out = []
    for row in rows:
        try:
            out.append((
                float(row["unix_time"]),
                float(row["read_bytes"]),
                float(row["write_bytes"]),
                (float(row["utime"]) + float(row["stime"])) / CLOCK_TICKS,
            ))
        except (KeyError, TypeError, ValueError):
            continue
    return out


def at(process, time):
    index = min(bisect_left([row[0] for row in process], time), len(process) - 1)
    return process[index]


def height_label(height):
    """Shows a height as `1200k` when it is a multiple of 1,000, else as the plain number."""
    return f"{height // 1000}k" if height % 1000 == 0 else str(height)


def band_label(band, next_band, size):
    """Labels a row with the heights that it covers.

    The metrics have one sample each second. When the height passes more than one band between
    two samples, the row covers all of those bands, and the label shows the full span.
    """
    start = height_label(band * size)
    if next_band is None:
        return f"{start}+"
    if next_band == band + 1:
        return start
    return f"{start}-{height_label(next_band * size)}"


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("run", type=Path)
    parser.add_argument("--band", type=int, default=100_000)
    args = parser.parse_args()
    if args.band <= 0:
        parser.error("--band must be a positive number of blocks")

    times, series = load_metrics(args.run / "metrics.csv")
    if not times:
        raise SystemExit(f"no {HEIGHT} samples in {args.run / 'metrics.csv'}")
    process = load_process(args.run / "processstats.csv")

    # The first sample at or after each band boundary.
    marks = []
    for index, height in enumerate(series["height"]):
        if height != height:  # NaN before the first commit
            continue
        band = int(height) // args.band
        if not marks or band > marks[-1][0]:
            marks.append((band, index))
    if marks and marks[-1][1] < len(times) - 1:
        marks.append((None, len(times) - 1))  # Close the last band, which is not complete.

    columns = [column for column, _, _ in SERIES]
    header = ["band", "wall_s", "blk/s"]
    if process:
        header += ["rd_MB/s", "wr_MB/s", "cpu"]
    header += columns
    print(" ".join(f"{name:>11}" for name in header))
    for (band, start), (next_band, end) in zip(marks, marks[1:]):
        wall = times[end] - times[start]
        if wall <= 0:
            continue
        blocks = series["height"][end] - series["height"][start]
        cells = [band_label(band, next_band, args.band), f"{wall:.0f}", f"{blocks / wall:.0f}"]
        if process:
            first, last = at(process, times[start]), at(process, times[end])
            cells += [
                f"{(last[1] - first[1]) / wall / 1e6:.0f}",
                f"{(last[2] - first[2]) / wall / 1e6:.0f}",
                f"{(last[3] - first[3]) / wall:.1f}",
            ]
        for column in columns:
            delta = series[column][end] - series[column][start]
            if column == "source_MB":
                delta /= 1e6
            cells.append(f"{delta:.0f}" if column in ("source_MB", "seal_rd_blk") else f"{delta:.1f}")
        print(" ".join(f"{cell:>11}" for cell in cells))


if __name__ == "__main__":
    main()
