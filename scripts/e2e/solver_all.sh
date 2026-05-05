#!/usr/bin/env bash
set -euo pipefail

tests=(
  happy_e2e_open_fill_settle
  failure_e2e_onchain
  failure_e2e_settlement
  api_e2e_orders
  admin_api_e2e
)

for test_name in "${tests[@]}"; do
  cargo test -p solver-e2e-tests --test "${test_name}" -- --ignored --test-threads=1 --nocapture
done
