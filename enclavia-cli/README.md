# enclavia-cli

The `enclavia` command-line binary. Drives the hosted Enclavia control plane.

```sh
enclavia auth login                              # browser-based OAuth, stores token in ~/.config/enclavia/
enclavia push myapp:v1                           # build/tag/push into <handle>/myapp:v1 on the registry
enclavia enclave create --image myapp:v1 \
    --egress-allow api.openai.com:443 \
    --egress-resolver 1.1.1.1
enclavia enclave list
enclavia enclave status <id>
enclavia enclave stop <id>
enclavia enclave start <id>
enclavia enclave destroy <id>
enclavia reproduce <id>                          # rebuild from pinned sources and compare PCRs
```

Configuration:

- `~/.config/enclavia/` holds credentials and config.
- `ENCLAVIA_BACKEND_URL` overrides the API endpoint (defaults to `https://api.beta.enclavia.io`). Useful when running against a local dev backend.

Also exposes a library face (`enclavia_cli::{api, commands, config}`) that other tools consume. The closed-source MCP server wraps these as MCP tools so Claude can drive the same operations from the chat.

The CLI is what most people interact with day to day; if it gets a feature, this is the surface to land it on first.

## License

Dual-licensed under Apache-2.0 OR MIT. See [`../LICENSE-APACHE`](../LICENSE-APACHE) and [`../LICENSE-MIT`](../LICENSE-MIT).
