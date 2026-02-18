#!/usr/bin/env bash
set -euo pipefail

cargo +nightly build -p scrambler-ebpf --target bpfel-unknown-none --release -Z build-std=core
cargo +nightly build -p scrambler-user
