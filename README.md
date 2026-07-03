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
bin/ui-manage login --api-key "$API_KEY" 192.168.1.1
bin/ui-manage login --username admin 192.168.1.1
```

Then run any information command against it:

```
bin/ui-manage identity
bin/ui-manage ports
bin/ui-manage clients --ip
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
| `completions SHELL` | Print a bash or zsh completion script |
| `report` | Run every information command against a device and print them together |
| `identity` | Device name, serial, MAC, firmware, and other identifiers |
| `cpu` / `memory` / `storage` | System health |
| `gateway` | Internet (WAN) status |
| `clients` | Every wired/wireless client on the network |
| `ports` | What's connected to each switch/gateway port |
| `power` | PoE devices/ports and their power state; `--on`/`--off "DEVICE:PORT"` toggles a port |
| `firewall` | Firewall rules |
| `port-forwards` | Port forwarding rules |
| `dhcp` | DHCP network configuration, leases, and reservations |

Most information commands support `--json` for raw output and
`--anon`/`--anonymous` to replace MAC addresses, IP addresses, and other
identifiers with realistic-looking placeholders — useful for sharing output
(bug reports, screenshots) without exposing real network details.

Pass `-v/--verbose` on any command to print the curl commands being executed
(secrets are always redacted).

## Shell completions

```
echo 'eval "$(bin/ui-manage completions bash)"' >> ~/.bashrc
echo 'eval "$(bin/ui-manage completions zsh)"'  >> ~/.zshrc
```

## Configuration

Device credentials are stored, encrypted, in `~/.config/ui-manage/config.toml`.
