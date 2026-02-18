#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update
sudo apt-get install -y llvm clang libbpf-dev pkg-config build-essential

rustup toolchain install nightly
rustup component add rust-src --toolchain nightly

cargo install bpf-linker
