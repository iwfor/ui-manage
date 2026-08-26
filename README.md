# ui-manage

A command-line tool for querying a UniFi controller (e.g. a UDM Pro) over its
REST API — device identity, gateway/WAN status, connected clients, switch
ports, firewall rules, port forwards, DHCP, and system health.

## Setup

```
bundle install
```

## Usage

Add a device, authenticating with either an API key (Network App 8.x+) or a
username/password:

```
bin/ui-manage login --api-key - 192.168.1.1     # prompts for the key (or reads piped stdin)
bin/ui-manage login --username admin 192.168.1.1
```

During `login` you are asked whether UniFi remote (cloud) access is expected on
this network. The answer is a policy decision the tool can't infer, and the
audit compares the controller against it; pass `--remote-access` or
`--no-remote-access` to answer non-interactively, or change it later with
`ui-manage policy`.

Pass `--verify-ssl` to `login` to enable TLS certificate verification for that
device (off by default, since UniFi controllers ship with self-signed
certificates); the setting is saved with the device.

Then run any information command against it:

```
bin/ui-manage identity
bin/ui-manage ports
bin/ui-manage clients --ip
bin/ui-manage clients --wired
bin/ui-manage report
```

If you manage multiple devices, use `-d/--device NAME` to target a
non-default one, or switch the default with `use-device`.

Run `bin/ui-manage help` for the full command list, or
`bin/ui-manage help COMMAND` for details on any one command.

## Commands

| Command | Description |
| --- | --- |
| `login HOST` | Add and authenticate a device |
| `use-device NAME` | Set the default device |
| `remove-device NAME` | Remove a configured device |
| `devices` | List configured devices |
| `policy` | Show or set a device's audit policy |
| `completions SHELL` | Print a bash or zsh completion script |
| `report` | Run every information command against a device and print them together |
| `identity` | Device name, serial, MAC, firmware, and other identifiers |
| `cpu` / `memory` / `storage` | System health |
| `gateway` | Internet (WAN) status |
| `clients [PATTERN]` | Every wired/wireless client on the network; `--wired`/`--wireless` filters by connection type |
| `ports` | What's connected to each switch/gateway port |
| `power` | PoE devices/ports and their power state; `--on`/`--off "DEVICE:PORT"` toggles a port |
| `firewall` | Firewall rules |
| `port-forwards` | Port forwarding rules |
| `dhcp` | DHCP network configuration, leases, and reservations |

Most information commands support `--json` for raw output and
`--anon`/`--anonymous` to replace MAC addresses, IP addresses, and other
identifiers with realistic-looking placeholders — useful for sharing output
(bug reports, screenshots) without exposing real network details.

Every command whose default output is a table supports `-s/--sort COLUMN`,
where `COLUMN` is a column name or a unique fragment of one (case-insensitive):

```
bin/ui-manage clients --sort mac
bin/ui-manage port-forwards --sort "int.port"
```

Pass `-v/--verbose` on any command to print the curl commands being executed
(secrets are always redacted).

## Shell completions

```
echo 'eval "$(bin/ui-manage completions bash)"' >> ~/.bashrc
echo 'eval "$(bin/ui-manage completions zsh)"'  >> ~/.zshrc
```

## Audit policy

Some findings depend on intent rather than on configuration alone — remote
access is a problem on one network and a requirement on the next. `policy`
records those decisions per device:

```
bin/ui-manage policy                      # show the current policy
bin/ui-manage policy --remote-access      # remote access is intended here
bin/ui-manage policy --no-remote-access   # remote access should be off
bin/ui-manage policy --unset              # back to "not configured"
```

Left unset, the audit reports the controller's actual setting without judging
it.

## Degraded checks

Not every controller exposes every endpoint: the admin interface, IDS/IPS
events, and several settings endpoints vary with the Network application
version, and an API key generally has less access than a local account — it
usually cannot read the admin list at all. Those endpoints are treated as
optional. When one is refused (HTTP 401/403/404, or an `api.err.NoPermission`
response), the reason is recorded and the checks that depend on it are
reported as skipped rather than passing silently or failing the whole run.

Core endpoints — devices, clients, networks, firewall rules, port forwards,
DHCP — are not optional; a failure there is a real error.

## Development

```
bundle install
bundle exec rake test
```

Tests run against a fake transport and never reach the network. They point
`UI_MANAGE_CONFIG_DIR` at a temporary directory, so the real
`~/.config/ui-manage` is never touched; set that variable yourself to keep a
separate profile.

## Configuration

Device credentials are stored, encrypted, in `~/.config/ui-manage/config.toml`.

## Security

- Credentials are encrypted with AES-256-GCM using a key in
  `~/.config/ui-manage/secret.key`. Both files are created `0600` (directory
  `0700`). Since the key lives next to the config, this protects against
  leaking `config.toml` alone (backups, pastes) — not against an attacker who
  can read your whole home directory.
- TLS verification is off by default to accommodate self-signed controller
  certificates; enable it per device with `login --verify-ssl`. The `devices`
  command shows each device's TLS mode.
- Secrets are passed to `curl` via a `0600` config file, never argv, so they
  don't appear in the process list. `--verbose` output always redacts them.
- Values written into that config file are escaped for curl's quoting rules,
  and headers carrying control characters are refused outright — the file is
  line-oriented, so an unescaped newline in a credential could otherwise
  inject an arbitrary curl directive.
- Gem versions are pinned exactly in the `Gemfile`. To check dependencies
  against the ruby-advisory-db:

  ```
  bundle exec bundle-audit check --update
  ```
