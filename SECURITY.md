# Security Policy

- Store signing and verification keys in environment variables or secret managers.
- Do not commit private keys.
- Audit logs intentionally exclude sensitive payload fields where possible.
- Report vulnerabilities privately to security@localhost.invalid.

## Logging guarantees
- No private key material is ever logged.
- Signature headers are validated but not persisted in clear form.
- Use log rotation for `audit.jsonl`.
