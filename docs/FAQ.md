# FAQ

1. **Is this an MCP server?**  
   No, it is a sidecar/reverse proxy in front of MCP servers.

2. **Can it block dangerous tools?**  
   Yes, use `deny_tools` and/or strict `allow_tools`.

3. **Do I need signatures?**  
   Optional, but recommended for trusted origin enforcement.

4. **Where are decisions stored?**  
   In JSONL audit logs at `--audit-log`.

5. **Can it enforce path constraints?**  
   Yes, via `allowed_paths` prefix checks.

6. **Will it run on macOS/Linux/Windows?**  
   Yes, via Rust cross-platform support.
