SHELL := /bin/bash

.PHONY: setup lint test demo doctor

setup:
	cargo fetch

lint:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings

test:
	cargo test --workspace

demo:
	cargo run -p mcp-firewall -- demo --output examples/output/demo-result.json

doctor:
	@command -v cargo >/dev/null || (echo "cargo is required" && exit 1)
	@command -v rustc >/dev/null || (echo "rustc is required" && exit 1)
	@cargo run -p mcp-firewall -- doctor
