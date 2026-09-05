# ui-manage

A command-line tool for querying and managing a UniFi controller (e.g. a UDM
Pro) over its REST API — device identity, gateway/WAN status, connected
clients, switch ports, firewall rules, port forwards, DHCP, and system health
to read; networks (VLANs), client pinning, DHCP reservations, and wireless
settings to change.

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
| `vlans` | Networks and VLANs with their segmentation settings and firewall zone |
| `vlan-create NAME` / `vlan-set NAME` / `vlan-delete NAME` | Create, change, and delete networks (VLANs) |
| `pins` / `pin CLIENT` / `unpin CLIENT` | Pin a client to a network (VLAN) whatever it connects through |
| `reserve CLIENT IP` / `unreserve CLIENT` | Reserve a static DHCP address for a client, or release it |
| `client-set CLIENT` | Change a client's settings — currently its name |
| `wlan-set SSID` | Change a wireless network: network/VLAN, guest, isolation, security, passphrase, band |
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

Every command that prints information — including `devices`, `policy`, and
`report` — takes `-j/--json` for raw output (`report --json` is one document
with a key per section; `audit --json` is shorthand for `--format json`).
The information commands also take `--anon`/`--anonymous` to replace MAC
addresses, IP addresses, and other identifiers with realistic-looking
placeholders — useful for sharing output (bug reports, screenshots) without
exposing real network details.

`alarms`, `events`, and `threats` read the controller's system log, which
is where Network application 9 moved all three (alarms are its entries at
warning severity and above, threats its security category); on an older
controller they fall back to the endpoints it replaced. `admins` reads the
controller-wide administrator list and shows the accounts with a role on the
site. No current endpoint reports whether an administrator has two-factor
authentication, so that column reads `unknown` and the audit check that
needs it is reported as not checked.

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

## Managing the network

The management commands change the controller. Each one resolves its target
by name first — the full name, or a unique part of it — and refuses to act
on an ambiguous match, a WAN network, or a value it can validate as wrong,
before anything is sent.

### Networks (VLANs)

```
bin/ui-manage vlan-create IoT --vlan 30 --subnet 192.168.30.1/24 --isolate
bin/ui-manage vlan-create Guest --vlan 20 --subnet 192.168.20.0/24 --guest
bin/ui-manage vlan-set IoT --no-internet --dhcp-range 192.168.30.100-192.168.30.199
bin/ui-manage vlan-set Lab --zone hotspot
bin/ui-manage vlan-delete Lab            # asks; --yes to skip, required when not a terminal
```

`--subnet` is the gateway address and prefix; given the network address
instead, the gateway becomes the first usable address. DHCP is on by default
from five addresses above the gateway to the last usable one. `--isolate`
blocks the network from every other network (UniFi's "Isolate Network"),
and `--no-internet` keeps it off the internet too.

`--guest` makes a guest network. On Network 9 and later, where the firewall
is zone-based, that means the Hotspot zone, whose clients reach the internet
and nothing internal (the controller marks such a network with the `guest`
purpose itself); on an older controller it is the legacy `guest` purpose.
`--isolate` is for ordinary networks only: the controller refuses it on a
guest network, which the zone already keeps from the LAN. `--zone NAME` puts
a network in any zone (`vlans` shows which zone each is in).

`vlan-delete` refuses while a wireless network or a pinned client still
uses the network, and lists them.

### Pinning clients to a VLAN

```
bin/ui-manage pin "Living Room TV" --vlan 30
bin/ui-manage pin aa:bb:cc:dd:ee:ff --network IoT
bin/ui-manage pins
bin/ui-manage unpin "Living Room TV"
```

A pin is UniFi's per-client network override: the client lands on that
network whatever SSID or switch port it arrives through, from its next
connection. A wired client only lands on the VLAN if its switch port carries
it (a trunk or "all" port profile rather than a single native VLAN). A client
may be given by name, hostname, MAC address, or IP address.

### Naming a client

```
bin/ui-manage client-set e4:24:6c:90:2d:48 --name "Front Door Camera"
bin/ui-manage client-set unknown-device --name Doorbell
bin/ui-manage client-set "Front Door Camera" --name ""    # back to its hostname
```

The name is what every view here shows for the client, and what the
controller shows in its own UI. A client that has never been named is
reached by its MAC address or the hostname it reports — `clients
--unknown` lists exactly those.

### Reserving a static IP address

```
bin/ui-manage reserve "Office Printer" 192.168.1.20
bin/ui-manage reserve aa:bb:cc:dd:ee:ff 192.168.30.10 --network IoT
bin/ui-manage unreserve "Office Printer"
bin/ui-manage dhcp --leases            # every reservation and dynamic lease
```

A reservation is UniFi's per-client "Fixed IP": the gateway hands the client
the same address every time, so the client stays on DHCP and nothing has to
be configured on the client itself. The address must be inside one of your
networks — that is the network the reservation is stored against, and
`--network NAME` picks it if more than one subnet contains the address.

An address already reserved for another client, the gateway's own address,
and a network or broadcast address are all refused before anything is sent;
if another client is currently holding the address on a dynamic lease, the
reservation is made and the collision reported. The client keeps its current
address until its lease expires, so reconnect it to take the new one now.

### Wireless networks

```
bin/ui-manage wlan-set ZombieGuest --network Guest --guest --isolate
bin/ui-manage wlan-set Zombieland --security wpa2-wpa3 --passphrase -
bin/ui-manage wlan-set setup --no-enabled
bin/ui-manage wlan-set Attic --band 5g,6g --hidden
```

`--network` is the LAN network the SSID's clients join, `--guest` applies
the controller's guest policy (and hotspot portal, if one is configured),
and `--isolate` stops the SSID's clients from seeing each other. Together
with a network made by `vlan-create --guest`, those three are what make an
SSID a guest network rather than a second door into the LAN — which is what
the `wlan_guest_network` audit check looks for.

`--security` is `open`, `wpa2`, `wpa3`, or `wpa2-wpa3`; WPA3 needs protected
management frames, so it sets `--pmf required` (`wpa2-wpa3` sets `optional`)
unless `--pmf` is given. `--passphrase -` reads the passphrase from a hidden
prompt, or from stdin when piped, so it stays out of shell history. The
passphrase is never printed back.

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

Not every controller exposes every endpoint: the administrator list, the
system log, and several settings endpoints vary with the Network application
version, and a credential may have less access than the account that created
it. Those endpoints are treated as optional. When one is refused (HTTP
401/403/404, or an `api.err.NoPermission` response), the reason is recorded
and the checks that depend on it are reported as skipped rather than passing
silently or failing the whole run.

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
bundle exec rake test      # 404 tests, no network
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
