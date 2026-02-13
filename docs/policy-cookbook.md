# Policy Cookbook

## Minimal safe policy
```yaml
firewall:
  allow_tools: ["tools.call"]
  deny_tools: []
  allowed_paths: ["/workspace"]
  max_body_bytes: 65536
  require_origin: false
  allowed_origins: []
  require_signature: false
  rate_limit_per_minute: 120
  sign_responses: false
```

## Strict production policy
```yaml
firewall:
  allow_tools: ["tools.call", "resources.read"]
  deny_tools: ["tools.delete", "tools.exec"]
  allowed_paths: ["/workspace/safe", "/workspace/readonly"]
  max_body_bytes: 32768
  require_origin: true
  allowed_origins: ["agent://prod-trusted"]
  require_signature: true
  rate_limit_per_minute: 60
  sign_responses: true
```
