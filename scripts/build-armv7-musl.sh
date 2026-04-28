#!/usr/bin/env bash
set -euo pipefail

TARGET="${TARGET:-armv7-unknown-linux-musleabihf}"
IMAGE="${IMAGE:-messense/rust-musl-cross:armv7-musleabihf}"
BIN_NAME="sia-dc09-mock"
OUT_DIR="target/${TARGET}/release"

docker run --rm \
  -v "$(pwd)":/home/rust/src \
  -w /home/rust/src \
  "$IMAGE" \
  cargo build --release --target "$TARGET"

ls -lh "${OUT_DIR}/${BIN_NAME}"
echo "Binary: ${OUT_DIR}/${BIN_NAME}"
