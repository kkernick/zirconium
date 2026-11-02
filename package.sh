#!/bin/bash

VERSION="${1}"
ROOT=$(git rev-parse --show-toplevel)

export CARGO_TARGET_DIR=${ROOT}/target
cargo build --release
fpm -t pacman --version $VERSION
