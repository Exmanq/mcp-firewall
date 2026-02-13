# Design Decisions

- **Rust + Tokio + Axum** for low-latency async proxy behavior.
- **YAML policy** chosen for readability and easy diff review.
- **JSONL audit** chosen for SIEM-friendly ingestion.
- **Ed25519** chosen for modern, compact signatures with mature libs.
- **Crate split (`proxy`, `policy`, `audit`, `cli`)** to keep boundaries clear.
