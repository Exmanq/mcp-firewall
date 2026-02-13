# Threat Model

## Assets
- MCP tool execution boundary
- Credentials inside MCP server runtime
- Audit integrity

## Main threats
- Prompt-injection triggered tool misuse
- Origin spoofing
- Request tampering
- Tool/path overreach
- Abuse via request floods

## Controls in v0.1.0
- Tool allow/deny
- Path allowlist prefixes
- Origin allowlist
- Optional Ed25519 verification
- Request size and rate limiting
- Append-only JSONL audit trail
