# enclavia-cli

The `enclavia` command-line binary. Drives the hosted Enclavia control plane: create attested enclaves, push Docker images into them, manage secrets, and confirm or revoke signed upgrades.

> **Agents**: the repo ships a machine-oriented guide at
> [`skills/enclavia/SKILL.md`](https://github.com/EnclaviaIO/enclavia/blob/master/skills/enclavia/SKILL.md)
> documenting every command's `--json` output shape and the recommended
> polling patterns. If you are an AI agent driving this CLI, start there.

## Install

Published on crates.io as
[`enclavia-cli`](https://crates.io/crates/enclavia-cli); the installed
binary is called `enclavia`.

```sh
cargo install enclavia-cli
```

Or via Nix, straight from this repo:

```sh
nix run github:EnclaviaIO/enclavia#enclavia -- --help
```

Prerequisites and upgrade paths are covered at
[docs.enclavia.io/install](https://docs.enclavia.io/install).

## Quickstart

The image is pushed *after* the enclave is created: each enclave owns its own
registry repo (`<your-handle>/<enclave-uuid>`), and the first push triggers
the measured EIF build.

```sh
enclavia auth login                       # browser OAuth; token lands in ~/.config/enclavia/
enclavia deploy myapp:v1 --name api --container-port 8080
#   -> create + push + build in one command; streams the build log and
#      prints the endpoint + PCRs once the enclave is running
```

`deploy` takes every `enclave create` flag. The three steps also exist
individually, which is what scripts and agents should use:

```sh
enclavia enclave create --name api --container-port 8080
#   -> prints the new enclave id; status starts as waiting_for_image
enclavia push myapp:v1 <enclave-id>       # docker tag + push; kicks off the build
enclavia enclave status <enclave-id>      # poll until running, then read the endpoint
```

Enclave ids accept any unique prefix, so `enclavia enclave status 3fa8` works
once it resolves to exactly one of your enclaves.

## Commands

Every command takes a global `--json` flag that replaces the human output
with a single machine-readable JSON value on stdout (see the SKILL.md for
the exact shapes).

### Enclaves

```sh
enclavia enclave create [FLAGS]      # see "Create flags" below
enclavia enclave list [--include-archived]
enclavia enclave status <id>
enclavia enclave logs <id>           # EIF build log + runtime log (runtime is debug/QEMU only)
enclavia enclave stop <id>
enclavia enclave start <id>
enclavia enclave restart <id>
enclavia enclave destroy <id>
```

### Create flags

| Flag | Meaning |
|------|---------|
| `--instance-type small\|medium\|large` | Enclave size (1/3/6 vCPU, 2/6/14 GB). Default `small`. |
| `--container-port N` | Port your container listens on. Default 8080. |
| `--name S` | Display name. |
| `--storage-size-bytes N` | Attach an encrypted persistent volume at `/data`. |
| `--visibility private\|public` | Who may connect through the proxy. Default private. |
| `--egress-allow HOST:PORT[/PROTO]` | Allow an outbound destination (repeatable). No flags = no egress. |
| `--egress-resolver IPV4` | DNS resolver for hostname allowlist entries (repeatable). |
| `--egress-config PATH` | Full egress policy as a JSON file instead of the flags above. |
| `--upgradable` | Allow signed image upgrades post-create (bakes a control key). |
| `--production` | Launch on real AWS Nitro hardware instead of a debug (QEMU) enclave. Requires a paid plan. |
| `--control-key KEY_NAME` | Self-hosted custody: register a local (YubiKey-backed) control key; the backend can then never sign upgrades itself. Implies `--upgradable`. |
| `--anti-rollback` | Synchronizer-backed storage anti-rollback (storage enclaves, entitled plans). |
| `--min-upgrade-delay DURATION` | Measured minimum upgrade activation delay (e.g. `48h`, `7d`), enforced by the enclave itself. Immutable post-create. |

All create-time flags are immutable: to change one, create a new enclave.

### Images

```sh
enclavia deploy <local-image> [FLAGS]      # create + push + watch until running (takes the create flags)
enclavia push <local-image> <enclave-id>   # docker tag + push into the enclave's repo
enclavia reproduce <enclave-id> [--upgrade <upgrade-id>]
```

`reproduce` rebuilds the EIF locally from the exact pinned sources the
backend used and compares the resulting PCRs, so you can independently
verify what an enclave attests to. Needs the `builder` checked out plus
`nix` and `docker` locally.

### Secrets

Injected into the container's environment inside the enclave; values never
appear in API responses.

```sh
enclavia secret set <enclave-id> NAME=value [NAME2=value2 ...]
enclavia secret set <enclave-id> --from-stdin --name NAME     # value from stdin
enclavia secret set <enclave-id> --from-file PATH --name NAME
enclavia secret list <enclave-id>
enclavia secret delete <enclave-id> NAME... [--yes]
```

### Upgrades

Staged image upgrades for `--upgradable` enclaves. New pushes stage instead
of deploying; nothing activates without a signed confirm.

```sh
enclavia upgrade list <enclave-id>
enclavia upgrade chain <enclave-id>       # the enclave's attested boot/upgrade history
enclavia upgrade confirm <enclave-id> <upgrade-id> [--at RFC3339 | --immediate]
enclavia upgrade revoke <enclave-id> <upgrade-id>
```

With managed custody the backend signs the confirmation for you. With
`--control-key` (self-hosted custody) confirm and revoke run a two-phase
prepare/sign/submit flow against your local key, so the signature happens on
your machine (or your YubiKey) and the backend never holds the private key.

### Control keys (self-hosted custody)

```sh
enclavia key generate --yubikey [--name NAME] [--slot 9c] [--touch-policy always] [--pin-policy once] [--serial N]
enclavia key import --yubikey [--name NAME] [--slot 9c] [--serial N]
enclavia key list
```

Keys are generated on-device (the private key never leaves the hardware);
the public half is recorded in `~/.config/enclavia/keys/index.json`.

### Auth

```sh
enclavia auth login
```

## Configuration

- `~/.config/enclavia/` holds credentials and the control-key index.
- `ENCLAVIA_BACKEND_URL` overrides the API endpoint (default
  `https://api.beta.enclavia.io`). Useful against a local dev backend.

## Library face

The crate also exposes `enclavia_cli::{api, commands, config}` for other
tools. The hosted MCP server at `mcp.beta.enclavia.io` wraps these as MCP
tools so Claude can drive the same operations from a chat.

The CLI is what most people interact with day to day; if a feature exists,
this is the surface it lands on first.

## License

Dual-licensed under Apache-2.0 OR MIT. See [`LICENSE-APACHE`](LICENSE-APACHE) and [`LICENSE-MIT`](LICENSE-MIT).
