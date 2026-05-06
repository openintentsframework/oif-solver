#!/usr/bin/env bash
set -euo pipefail

tests=(
  happy_e2e_open_fill_settle
  submit_e2e_hyperlane
  permit2_e2e
  eip3009_e2e
  deny_list_e2e
  failure_e2e_onchain
  failure_e2e_settlement
  api_e2e_orders
  admin_api_e2e
)

for test_name in "${tests[@]}"; do
  echo "==> Running ${test_name}"
  # Per-test timeout so a hung run doesn't block the whole suite. Override
  # via E2E_TEST_TIMEOUT (e.g. "30m"). `timeout` may not be on every host
  # (notably some macOS setups without coreutils), so degrade gracefully.
  if command -v timeout >/dev/null 2>&1; then
    timeout "${E2E_TEST_TIMEOUT:-20m}" \
      cargo test -p solver-e2e-tests --test "${test_name}" \
        -- --ignored --test-threads=1 --nocapture
  else
    cargo test -p solver-e2e-tests --test "${test_name}" \
      -- --ignored --test-threads=1 --nocapture
  fi
done
