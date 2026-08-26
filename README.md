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
| `audit [CATEGORY]` | Run a health and security audit |
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
| `vlans` | Networks and VLANs with their segmentation settings |
| `vpn` | VPN servers and site-to-site tunnels |
| `routes` | Static routes and dynamic DNS entries |
| `wlans` | Wireless networks and their security settings; `--insecure-only` |
| `wifi-experience` | Per-client signal, SNR, retries, and satisfaction |
| `rogue-aps` | Neighbouring access points, flagging any using your SSIDs |
| `firmware` | Firmware versions and available updates |
| `port-errors` | Ports reporting errors, drops, or a duplex fault |
| `health` | Controller subsystem health |
| `settings` | Site settings; `--section NAME` |
| `admins` | Site administrators, roles, and 2FA state |
| `alarms` / `events` / `threats` | Outstanding alarms, the event log, and IDS/IPS detections |

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
(secrets are always redacted). `--timeout SECONDS` sets how long to wait for
each controller request (default 30); an audit reads many endpoints, so its
worst case is that timeout times the number of them.

## Shell completions

```
echo 'eval "$(bin/ui-manage completions bash)"' >> ~/.bashrc
echo 'eval "$(bin/ui-manage completions zsh)"'  >> ~/.zshrc
```

## Auditing

```
bin/ui-manage audit                    # everything
bin/ui-manage audit security           # or health
bin/ui-manage audit --severity high    # only what matters most
bin/ui-manage audit --list-checks      # what it looks at
bin/ui-manage audit --explain wlan_pmf # what one check means
```

Each check reports one of four outcomes, and the last two are kept apart
deliberately:

| | |
| --- | --- |
| **pass** | ran, found nothing |
| **fail** | found something, reported as findings |
| **skipped** | could not run — the controller or this credential would not provide the data. **Not a pass**, and listed separately so it cannot be read as one |
| **errored** | the check itself failed. The run continues; the exit status is 2 |

API keys in particular cannot read the admin interface on most controllers,
so a run authenticated with one will skip several checks and say so.

Findings are ranked `info`, `low`, `medium`, `high`, `critical`.

### What it checks

`ui-manage audit --list-checks` prints this from the registry, and
`--explain ID` describes one in full.

<!-- begin: check catalog -->
<!-- Generated by `rake catalog`. Do not edit by hand. -->

### Health (18)

| Check | Default severity | What it looks for |
| --- | --- | --- |
| `device_cpu` | high | Device CPU above threshold |
| `device_memory` | high | Device memory above threshold |
| `device_offline` | critical | Adopted device not connected |
| `device_recent_reboot` | medium | Device restarted recently |
| `device_storage` | high | Controller storage above threshold |
| `device_temperature` | high | Device temperature above threshold |
| `dhcp_pool_exhaustion` | high | DHCP pool approaching exhaustion |
| `dhcp_reservation` | high | Conflicting or out-of-range DHCP reservation |
| `firmware_update_available` | medium | Firmware update available |
| `poe_budget` | high | PoE draw approaching the switch budget |
| `port_duplex` | medium | Live link negotiated at half duplex |
| `port_errors` | medium | Switch port error rate above threshold |
| `radio_channel_overlap` | medium | Access points sharing a channel |
| `radio_utilization` | medium | Radio channel utilization above threshold |
| `subnet_overlap` | high | Networks configured on overlapping subnets |
| `wan_latency` | high | Internet uplink latency or loss above threshold |
| `wan_status` | critical | Internet uplink down or running on failover |
| `wifi_client_quality` | medium | Wireless clients with weak signal or high retry rate |
### Security (21)

| Check | Default severity | What it looks for |
| --- | --- | --- |
| `admin_super_count` | medium | More super administrators than the configured maximum |
| `admin_two_factor` | high | Administrator without two-factor authentication |
| `auto_firmware_updates` | medium | Automatic firmware updates disabled |
| `controller_tls` | medium | Controller TLS certificate not verified |
| `device_ssh` | medium | Device SSH access enabled |
| `device_unadopted` | high | Device present but not adopted |
| `firewall_permissive_rule` | critical | Firewall rule accepting any source to any destination |
| `firewall_rule_logging` | low | Blocking firewall rule without logging |
| `firewall_unused_group` | info | Firewall group not referenced by any rule |
| `ips_disabled` | high | Intrusion prevention disabled or in detect-only mode |
| `ips_recent_detections` | high | Recent intrusion detections |
| `port_forward_open_source` | high | Port forward open to any source address |
| `port_forward_sensitive` | critical | Port forward exposing a sensitive service to the internet |
| `remote_access` | medium | Cloud remote access disagrees with the configured policy |
| `rogue_ap_impersonation` | critical | Unmanaged access point broadcasting one of our SSIDs |
| `snmp_insecure` | high | SNMP v1/v2c enabled, or using a default community string |
| `upnp_enabled` | high | UPnP allows clients to open the firewall themselves |
| `wlan_encryption` | critical | SSID with absent or broken encryption |
| `wlan_guest_network` | high | Guest SSID on a network without guest treatment |
| `wlan_passphrase` | high | SSID passphrase shorter than the configured minimum |
| `wlan_pmf` | medium | SSID without protected management frames |

<!-- end: check catalog -->

### On a schedule

`--fail-on` sets the exit status, which is what makes this usable from cron
or CI:

```
bin/ui-manage audit --fail-on high --format json --output audit.json
```

| Exit | Meaning |
| --- | --- |
| `0` | nothing at or above the threshold |
| `1` | findings at or above it |
| `2` | a check errored, so the run is incomplete |

A baseline reports only what has changed since a known-good run — and what
has since been fixed:

```
bin/ui-manage audit --save-baseline ~/net-baseline.json
bin/ui-manage audit --baseline ~/net-baseline.json --fail-on high
```

### Output

`--format` renders a table (default), `json`, `markdown`, or a
self-contained `html` page; `--output FILE` writes to a file. `--summary`
prints counts only, `--all` includes checks that passed, and `--remediate`
adds how to fix each finding.

## Sharing output safely

Passwords, passphrases, pre-shared keys, RADIUS secrets, and SNMP
communities are replaced with a placeholder in every form of output —
tables and `--json` alike. `wlans` reports only whether a passphrase is set
and how long it is, which is what an audit needs; `--anon` drops the length
too.

This is not a flag you can turn off. Nothing the tool needs to display
requires the real value, and audit output tends to end up in tickets and
chat. Checks that must reason about a secret (passphrase length, say) see
the raw value internally — redaction happens where output is rendered.

`--anon`/`--anonymous` additionally replaces identifying values with
realistic-looking placeholders: IP addresses (from the RFC 5737
documentation ranges), MAC addresses (from a locally-administered prefix
never assigned to real hardware), serial numbers, SSIDs, device and client
names, and administrator names and email addresses.

The same real value always maps to the same placeholder within one run, so
entries stay cross-referenceable across sections — and a name replaced in
one column is replaced everywhere it appears in free text, including inside
audit findings.

Between the two, `--json --anon` is a safe way to capture real controller
output for a bug report, or as a fixture to develop a check against.

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

## Writing an audit check

The audit engine lives in `lib/ui_manage/audit/`. A check is one file under
`audit/checks/`; subclassing registers it, so there is no other wiring.

```ruby
module UiManage
  module Audit
    module Checks
      class GuestIsolation < Check
        id          :guest_isolation
        title       'Guest network without client isolation'
        category    :security          # security or health
        severity    :high              # info, low, medium, high, critical
        requires    :networks          # endpoints this check cannot run without
        remediation 'Settings > Networks > (network) > Advanced: enable isolation.'

        def run
          data(:networks).each do |net|
            next unless net['is_guest']
            next if net['network_isolation_enabled']

            finding(
              subject:  net['name'],
              message:  "#{net['name']} is a guest network without client isolation.",
              evidence: { 'vlan' => net['vlan'] }
            )
          end
        end
      end
    end
  end
end
```

What the base class gives you:

- `requires` — the runner skips the check, with the reason the endpoint was
  refused, when the controller or credential will not serve that data. A
  check body never has to handle `nil`.
- `data(:name)` — an endpoint, fetched once per run and shared by every
  check.
- `threshold('cpu_percent')` — a tunable value, from `audit.toml` or the
  built-in default.
- `policy(:remote_access_expected)` — what the operator said this network is
  supposed to look like (see `ui-manage policy`).
- `setting('mgmt')` — one section of the controller's site settings.
- `finding(...)` — something wrong. `severity:` overrides the check's default
  for a single finding.
- `skip!('reason')` — end as "not checked". Use it whenever the data does
  not say enough to judge; a check must never pass by default.

A run reports four outcomes per check: **pass**, **fail**, **skip**, and
**error**. These are kept apart deliberately — a skip means the data was
unavailable, an error means the check has a bug, and reporting either as a
pass would let "not checked" read as "fine".

### Tuning

Thresholds and suppressions live in `~/.config/ui-manage/audit.toml`:

```toml
[thresholds]
cpu_percent = 80
min_passphrase_chars = 12

[suppress]
# Whole checks to stop running.
checks = ["wlan_hidden_ssid"]
# Individual findings, as "check_id" or "check_id:subject".
findings = ["port_forward_sensitive:Plex"]
```

Suppression exists so a finding the operator has considered and accepted
stops reappearing — a recurring known-good finding trains people to ignore
the whole report.

## Development

```
bundle install
bundle exec rake test      # 377 tests, no network
bundle exec rake catalog   # regenerate the check table above
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
