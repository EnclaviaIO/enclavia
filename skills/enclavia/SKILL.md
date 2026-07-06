---
name: enclavia
description: Manage Enclavia confidential-compute enclaves (create, list, status, logs, stop/start/restart/destroy, push images, secrets, staged upgrades) via the `enclavia` CLI with `--json`; use when a task asks to deploy, inspect, or operate an Enclavia enclave from a terminal or agent.
---

# enclavia CLI (agent guide)

The `enclavia` binary manages enclaves over the Enclavia backend REST API.
With `--json` every command is fully scriptable, which is more
token-efficient than the MCP server at mcp.beta.enclavia.io for the same
operations.

## The rule

1. ALWAYS pass `--json` (global flag, either position works).
2. Parse stdout as a single JSON value.
3. Branch on the EXIT CODE, not on prose:
   - exit 0: stdout is the success object/array.
   - exit non-zero: stdout is `{"error": "<message>", "kind": "<kind>"}`
     (`kind` is one of `not_logged_in`, `unauthorized`, `error`).
   - Exception: `reproduce` is a verification command (exit 0 = reproducible,
     exit 2 = diverged, with the reproduce payload still on stdout). See its entry.
4. stderr is human progress/diagnostics only; ignore it unless debugging.

## Auth (do this first)

The CLI reads credentials from `~/.config/enclavia/credentials.json`
(honours `$XDG_CONFIG_HOME`). The file holds an OAuth access token plus a
refresh token; the CLI auto-refreshes on expiry and rewrites the file, so
once it exists an agent keeps working with no further interaction.

`enclavia auth login` is INTERACTIVE: it opens a browser (OAuth 2.1 +
PKCE) and prints the approval URL to stderr. A headless agent CANNOT
complete it. Have a human run `enclavia auth login` once on a machine with
a browser to create the credentials file, then run the agent with that
file present (copy it to the agent's `~/.config/enclavia/` if needed). If
no credentials exist, commands fail with `{"kind":"not_logged_in"}`.

Set `ENCLAVIA_BACKEND_URL` (default `https://api.beta.enclavia.io`) to
target a non-prod backend, e.g. `http://localhost:3000`. Note the
credentials file also records the backend it was minted against and is
used as the base URL; keep them consistent.

## Command reference (--json shapes)

Identifiers: `<id>` accepts a unique id prefix anywhere a full UUID works.

- `enclavia auth login --json`
  -> `{"status":"logged_in","handle":<str|null>,"backend_url":<str>}` (interactive; see Auth).

- `enclavia enclave list [--include-archived] --json`
  -> JSON ARRAY of enclave objects: `{id,name,docker_image,status,instance_type,created_at,archived, ...}`.

- `enclavia enclave status <id> --json`
  -> one enclave object: `{id,name,status,status_detail?,mode,instance_type,docker_image,vsock_cid,endpoint?,created_at,pcrs?,error_message?}`.

- `enclavia enclave logs <id> --json`
  -> `{"build_log":<str|null>,"runtime_log":<str|null>}`. `build_log` is the EIF build output (always available once building); `runtime_log` is the guest serial console, captured only for debug/QEMU enclaves (null on production Nitro). `--json` emits the raw object verbatim (pipe into a log viewer); without it the two logs print as labeled sections. Good first stop when `status` shows `error` or a build/boot failure.

- `enclavia enclave create [--instance-type small|medium|large] [--container-port N] [--storage-size-bytes N] [--name S] [--visibility private|public] [--upgradable] [--egress-allow HOST:PORT[/PROTO]]... [--egress-resolver IPV4]... [--egress-config PATH] --json`
  -> created enclave object `{id,status,...}`. Status starts `waiting_for_image`; next step is `push`.

- `enclavia enclave stop|start|restart|destroy <id> --json`
  -> `{"id":<id>,"status":"stopped"|"started"|"restart_requested"|"destroyed"}`.

- `enclavia push <local-image> <id> --json`  (needs local `docker`)
  -> `{"image":"<registry>/<owner>/<uuid>:latest","digest":"sha256:..."|null,"triggered":[<id>...],"staged":[{enclave_id,upgrade_id,image}],"rejected_non_upgradable":[<id>...]}`.
  Pushing to a non-upgradable enclave that already has an image is an error (non-zero exit).

- `enclavia reproduce <id> [--upgrade <upgrade-id>] --json`  (needs local `builder` + `nix`)
  -> `{enclave_id,image_digest,expected{PCR0,PCR1,PCR2},actual{...},mismatches[],reproducible:<bool>,recorded_builder_rev,recorded_crates_rev,...}`.
  Verification command: exit 0 = reproducible, exit 2 = diverged (stdout still
  carries the full payload incl. `mismatches`), exit 1 = operational error. Gate
  on exit 0 (or `reproducible == true`).

- `enclavia secret list <id> --json`
  -> ARRAY of `{name,created_at,updated_at,pending}`. Values are NEVER returned.

- `enclavia secret set <id> NAME=value [NAME2=value2 ...] --json`  (or `--from-stdin --name NAME` / `--from-file PATH --name NAME`)
  -> `{"enclave_id":<id>,"set":[names],"updated":N,"restart_required":<bool>}`. Names match `^[A-Z_][A-Z0-9_]*$`. Run `enclave restart` to apply.

- `enclavia secret delete <id> NAME... --yes --json`
  -> `{"enclave_id":<id>,"deleted":[names],"updated":N,"restart_required":<bool>}`. `--yes` is REQUIRED with `--json` (no interactive prompts).

- `enclavia upgrade list <id> --json`
  -> ARRAY of staged-upgrade objects `{id,status,docker_image,image_digest?,valid_from?,created_at}`.

- `enclavia upgrade chain <id> --json`
  -> `{enclave_id,upgradable,image_digest,pcrs,control_public_key?,debug_mode,tip_matches_row,links:[{kind,sequence,validation,...}]}` (locally re-verified).

- `enclavia upgrade confirm <id> <upgrade-id> [--at RFC3339 | --immediate] --json`
  -> updated staged-upgrade object. Default schedule is now + 7 days.

- `enclavia upgrade revoke <id> <upgrade-id> --json`
  -> updated staged-upgrade object (cancelled).

## Examples

Create, push, and poll until running:
```
enclavia enclave create --container-port 8080 --name api --json
# {"id":"<uuid>","status":"waiting_for_image",...}
enclavia push myapp:latest <uuid> --json
# {"image":".../<uuid>:latest","digest":"sha256:...","triggered":["<uuid>"],...}
# poll: read .status until "running", then read .endpoint
enclavia enclave status <uuid> --json
```

List enclaves:
```
enclavia enclave list --json     # [{id,name,status,docker_image,...}, ...]
```

Rotate a secret, then apply it:
```
enclavia secret set <uuid> API_KEY=sk-... --json   # {...,"restart_required":true}
enclavia enclave restart <uuid> --json             # {"id":"<uuid>","status":"restart_requested"}
```
