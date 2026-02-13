# Configuration

## CLI flags
- `mcp-firewall run --config <path>`: required policy yaml.
- `--upstream <url>`: required upstream MCP server base URL.
- `--listen <host:port>`: firewall bind address (default `127.0.0.1:8787`).
- `--audit-log <path>`: JSONL path (default `audit.jsonl`).
- `--verify-key-hex <hex>`: Ed25519 public key (32-byte hex).
- `--sign-key-hex <hex>`: Ed25519 private key seed (32-byte hex).

## Policy file (`policy.yml`)
```yaml
firewall:
  allow_tools: ["tools.call"]
  deny_tools: ["tools.delete"]
  allowed_paths: ["/safe"]
  max_body_bytes: 65536
  require_origin: true
  allowed_origins: ["agent://trusted"]
  require_signature: true
  rate_limit_per_minute: 120
  sign_responses: true
```

## Environment variables
- `MCP_FIREWALL_VERIFY_KEY_HEX`
- `MCP_FIREWALL_SIGN_KEY_HEX`
- `MCP_FIREWALL_UPSTREAM`
- `MCP_FIREWALL_LISTEN`
