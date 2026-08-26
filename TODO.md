# Health & security audit — roadmap

Turning `ui-manage` from a set of read commands into a tool that can run a
full health and security audit of a UniFi-managed network.

Status key: `[x]` done · `[~]` in progress · `[ ]` not started

---

## Phase 1 — API layer  ✅ done (commit 79b3189)

- [x] Declare site-scoped endpoints as data (`NETWORK_ENDPOINTS`) and define
      the readers from it
- [x] `wlans` → `/rest/wlanconf`
- [x] `settings` → `/get/setting`
- [x] `health` → `/stat/health`
- [x] `alarms` → `/stat/alarm`, `events` → `/stat/event` (with `within`)
- [x] `ips_events` → `/stat/ips/event`
- [x] `admins` → `POST /cmd/sitemgr {cmd: get-admins}`
- [x] `rogue_aps` → `/stat/rogueap`
- [x] `routes` → `/rest/routing`, `dynamic_dns` → `/rest/dynamicdns`
- [x] `radius_profiles` → `/rest/radiusprofile`, `radius_accounts` → `/rest/account`
- [x] `port_profiles` → `/rest/portconf`
- [x] `user_groups` → `/rest/usergroup`, `dpi_apps` → `/rest/dpiapp`
- [x] `site_stats` → `POST /stat/report/daily.site`
- [x] UniFi OS endpoints (`os_system`, `os_users`) — bare JSON, no envelope
- [x] Query-param support on `network_get`; `network_post`
- [x] Per-run response cache, invalidated on write
- [x] `EndpointUnavailable` + `Client#optional` + `#degradations` — degraded
      checks when a credential or controller version won't serve an endpoint
- [x] Extract `CurlTransport` so `Client` is testable without a network
- [x] Per-device audit policy in config: `remote_access_expected`, prompted
      during `login`, viewable/changeable via `policy`
- [x] Test suite (minitest + rake), 91 tests, fake transport, temp config dir

**Verify against a real controller before Phase 4 depends on them:** the
paths for `/cmd/sitemgr`, `/rest/dpiapp`, and `/stat/ips/event` vary by
Network application version. All three are optional, so a wrong guess
degrades rather than breaks.

---

## Phase 2 — New read commands  ✅ done

Each follows the existing pattern: `desc` + `output_options` + `--sort`, with
a `show_*` helper reused by `report`. All of them read optional endpoints, so
all of them degrade with a printed reason rather than aborting.

- [x] `Redactor` — strip `x_`-prefixed and plainly-named secrets at the render
      boundary; wired into `Formatter.json` so no caller can forget
- [x] `wlans` — SSID, band, security, cipher, PMF, WPS, guest, hidden, VLAN;
      `--insecure-only`
- [x] `settings` — flattened site settings; `--section NAME`
- [x] `health` — subsystem status
- [x] `alarms` — `--within HOURS`, `--archived`
- [x] `events` — `--within HOURS`, `--type PATTERN`, `--limit N`
- [x] `threats` — IDS/IPS detections; `--within HOURS`, `--severity`
- [x] `admins` — accounts, role, super, 2FA
- [x] `rogue-aps` — `--within HOURS`, `--min-signal`, flags SSIDs matching ours
- [x] `vpn` — VPN servers/peers derived from `networkconf`
- [x] `vlans` — subnet, VLAN ID, purpose, isolation, DHCP; `--all`
- [x] `routes` — static routes + dynamic DNS
- [x] `firmware` — current vs available version per device; `--outdated`
- [x] `wifi-experience` — RSSI, SNR, retries, satisfaction; `--signal-below`
- [x] `port-errors` — RX/TX errors, drops, duplex faults; `--all`
- [x] Extend `clients` with `--unknown`, `--guest`, `--vlan N`, `--since HOURS`
- [x] Fold the new sections into `report` (events excluded — raw log)
- [x] Tests for every new view, plus report integration tests
- [x] README

Decisions taken along the way:
- `port-errors` is its own command rather than a `--errors` flag on `ports`,
  to avoid two code paths over the same port table.
- `--unknown` on `clients` means "no user-assigned name" — `/rest/user` lists
  every client ever seen, so absence from it is almost never the signal.
- Alarms have no severity field on the controller, so `alarms --severity` was
  dropped; `threats --severity` uses `inner_alert_severity` (Suricata numbers
  1 as most severe, so the rank is inverted for filtering).
- Views live in `lib/ui_manage/audit_views.rb` rather than growing `cli.rb`;
  `cli.rb` keeps only the Thor command definitions.
- `window_hours` / `record_limit` exist because `report` runs the views
  outside their own commands, where `options[:within]` is not in scope.
- Secret redaction sits in `Formatter.json` rather than each caller, so a
  new command cannot forget it. `--anon` was extended to SSIDs, device
  names, and admin identities.
- Impersonation detection on `rogue-aps` reports `?` rather than `no` when
  the WLAN list cannot be read — "unanswerable" must not read as "checked".

Still worth doing before Phase 4 leans on this data:
- [ ] Verify `/cmd/sitemgr`, `/rest/dpiapp`, `/stat/ips/event`, and the 2FA
      field name against the real controller
- [ ] `settings` output is long; a `--section` default or a summary view may
      be wanted once the audit consumes it

## Phase 3 — Check engine  ✅ done

- [x] `Audit::Check` — declarative id/title/category/severity/requires/
      remediation, `#run`, `finding(...)`, `skip!(reason)`
- [x] `Audit::Finding` — check id, severity, subject, message, evidence,
      remediation; `key` for suppression
- [x] `Audit::Context` — fetches each endpoint once per run, shared across
      checks; carries degradation reasons, thresholds, and device policy
- [x] `Audit::Registry` — subclasses self-register, filterable by id (glob),
      category, severity, and suppression
- [x] `Audit::Runner` + `Audit::Report` — runs checks, applies suppression,
      summarises, and computes an exit status
- [x] `Audit::Settings` — thresholds and suppressions from
      `~/.config/ui-manage/audit.toml`, with built-in defaults
- [x] `Audit::Severity` — info/low/medium/high/critical with ordering
- [x] Four result states, not three: pass / fail / **skip** / **error**
- [x] Five reference checks proving the mechanics end to end
- [x] Shared `WlanSecurity` and `DeviceState` modules so checks and views
      cannot disagree
- [x] 71 new tests

Decisions taken along the way:
- Four result states rather than three. A skip (data unavailable, expected)
  and an error (the check has a bug) are different facts, and conflating
  either with a pass would let "not checked" read as "fine". A check that
  raises is caught, recorded, and the run continues.
- `requires` on a check is what connects Phase 1's degradation tracking to
  the engine: the runner skips the check with the recorded reason, so no
  check body ever handles a nil endpoint.
- `skip!` exists for the other case — the endpoint answered, but the data
  does not say enough to judge (a setting the controller does not report).
- An errored check forces exit status 2 regardless of `--fail-on`: a run
  that could not complete must not report success.
- Suppression is by `check_id` or `check_id:subject`, so one accepted
  finding can be silenced without disabling the whole check.

Reference checks shipped (the rest come in Phases 4 and 5):
`wlan_encryption`, `wlan_passphrase`, `remote_access`, `device_offline`,
`device_cpu`.

**Not yet reachable from the CLI** — the `audit` command is Phase 6. The
engine is exercised through tests until then.

## Phase 4 — Security checks  ✅ done

21 security checks ship. Each is one file under `lib/ui_manage/audit/checks/`.

**Wireless**
- [x] `wlan_encryption` — open / WEP / WPA1 / TKIP / WPS, one finding per
      weakness, severity per weakness
- [x] `wlan_passphrase` — shorter than `min_passphrase_chars`
- [x] `wlan_pmf` — protected management frames disabled
- [x] `wlan_guest_network` — guest SSID mapped to a non-guest network
- [x] `rogue_ap_impersonation` — unmanaged AP broadcasting one of our SSIDs

**Perimeter**
- [x] `port_forward_sensitive` — forwards covering `sensitive_ports`
- [x] `port_forward_open_source` — forward accepting any source
- [x] `upnp_enabled`
- [x] `remote_access` — controller vs. `ui-manage policy` (Phase 3)
- [x] `controller_tls` — this tool connecting without certificate verification

**Firewall**
- [x] `firewall_permissive_rule` — any-to-any accept, critical from the WAN
- [x] `firewall_rule_logging` — blocking rules without logging (one finding
      for the set, not one per rule)
- [x] `firewall_unused_group`

**Access control**
- [x] `admin_two_factor` — critical for super admins; skips entirely when the
      controller reports no 2FA state; reports the gap at info when it
      reports for some accounts and not others
- [x] `admin_super_count` — above `max_super_admins`
- [x] `device_ssh` — enabled; password-only outranks key-based
- [x] `snmp_insecure` — v1/v2c enabled, default community string

**Threat posture**
- [x] `ips_disabled` — off, or detect-only
- [x] `ips_recent_detections` — grouped by signature
- [x] `auto_firmware_updates`
- [x] `device_unadopted` — pending adoption or failed adoption

Supporting work:
- [x] `Check#setting_value` — reads a settings field, skipping when the
      controller does not report it. Several field names may be given, since
      they drift across versions.
- [x] Shared `PortSpec` (port ranges/lists), `AdminAccount` (2FA state),
      `WlanSecurity.ssid_names`/`impersonates?`
- [x] 50 new tests

Decisions taken along the way:
- Settings-backed checks all route through `setting_value`, because the
  dangerous failure is silent: a field the controller never sent reads as
  nil, nil looks falsy, and the check would report "SSH is disabled" about a
  controller that never mentioned SSH. They skip instead.
- `firewall_rule_logging` emits one finding for the whole set. A site that
  never enabled logging would otherwise bury every other finding.
- Credentials never reach a Finding: `wlan_passphrase` reports length,
  `snmp_insecure` reports "is a default" rather than the community string.

Deferred, with reasons — worth revisiting:
- [ ] Inter-VLAN restriction between IoT/guest and trusted networks. Needs
      rules cross-referenced against networks; the most valuable check still
      missing.
- [ ] WAN-facing management (SSH/HTTPS reachable from the internet). Needs
      `WAN_LOCAL` rule analysis.
- [ ] Weak/default RADIUS shared secret. Did not want to guess the field
      name without a real controller to check against.
- [ ] Firmware with a known advisory. Needs a bundled advisory list and a
      refresh mechanism — a project of its own.
- [ ] IPS signature set staleness. No signature-date field confirmed.
- [ ] Unknown client on a trusted VLAN; IoT-OUI client on the default VLAN.
      Both are noisy without tuning, and the second needs an OUI database.
- [ ] Untrusted switch port without 802.1X or isolation.

Dropped deliberately:
- `WAN_IN` default-accept — `/rest/firewallrule` does not expose the
  per-ruleset default action.
- Disabled security-relevant rules — no way to tell "disabled by mistake"
  from "disabled deliberately"; it would be pure noise.
- SSID on the management VLAN — no reliable way to identify which network is
  the management one from the API.
- DDNS credentials in cleartext — the controller must store a usable
  credential for DDNS to work, so this is not actionable.
- Admin idle >90 days — the admin payload carries no reliable last-login
  time.

## Phase 5 — Health checks  ✅ done

18 health checks ship, bringing the registry to 39.

**Devices**
- [x] `device_offline` (Phase 3)
- [x] `device_cpu` (Phase 3)
- [x] `device_memory` — from a reported percentage or raw totals
- [x] `device_temperature` — named sensor arrays or a single field
- [x] `device_storage`
- [x] `device_recent_reboot`
- [x] `firmware_update_available`

**Uplink**
- [x] `wan_status` — down, and running on failover while the primary is up
- [x] `wan_latency` — latency and loss

**Ports**
- [x] `port_errors` — judged as a rate, not a count
- [x] `port_duplex`
- [x] `poe_budget`

**Addressing**
- [x] `dhcp_pool_exhaustion`
- [x] `subnet_overlap`
- [x] `dhcp_reservation` — duplicates and out-of-range

**Wireless**
- [x] `wifi_client_quality` — RSSI floor and retry rate
- [x] `radio_channel_overlap` — same and adjacent channels on 2.4 GHz
- [x] `radio_utilization`

Supporting work:
- [x] New thresholds: `poe_budget_percent`, `port_error_rate_percent`
- [x] `Client.gateway_of` extracted so `Context#gateway` picks the same
      device the client does
- [x] 47 new tests

Decisions taken along the way:
- `port_errors` judges an error *rate* against packets, not a raw count.
  The counters are cumulative since boot, so a raw threshold would either
  miss a failing port on a freshly rebooted device or flag every healthy
  port on one that has been up a year.
- Checks that measure something not every device reports — temperature, PoE
  budget, radio utilization — skip when *nothing* reports it, rather than
  passing. Passing would claim the fleet is cool, or under budget, when
  nothing was measured.
- A missing WAN loss figure is left alone rather than read as zero loss.
- `wifi_client_quality` groups into one finding per problem rather than one
  per client: on a busy network the individual clients change constantly and
  the actionable fact is how many there are.
- `radio_channel_overlap` treats 2.4 GHz separately, where channels are
  20 MHz wide but 5 MHz apart, so neighbours interfere even on different
  numbers. 5 and 6 GHz only overlap on an exact match.

Deferred, with reasons:
- [ ] NTP synchronisation. The settings carry the configured servers but not
      whether the clock is actually in sync.
- [ ] Site backup age. No endpoint for listing backups confirmed.
- [ ] Alarm count against a 7-day baseline. Belongs with the `--baseline`
      work in Phase 6, which is where trend comparison lives.
- [ ] Port speed below what the port and cable can carry. `speed_caps` is a
      bitmask that needs decoding against each model.

## Phase 6 — `audit` command  ✅ done

- [x] `audit [CATEGORY]` — all / `security` / `health`
- [x] `--severity LEVEL`
- [x] `--fail-on LEVEL` — exit 0 clean / 1 findings / 2 errored
- [x] `--format table|json|markdown|html`
- [x] `--check` / `--skip`, glob-friendly
- [x] `--list-checks`, `--explain ID`, `--summary`, `--all`, `--remediate`
- [x] `--anon` throughout
- [x] `--output FILE`
- [x] `--baseline FILE` / `--save-baseline FILE`, reporting what is new and
      what has been resolved
- [x] `audit` sits with `report` in its own tier in `sort_commands!`
- [x] Audit summary folded into `report`
- [x] Renderers (moved forward from Phase 7): table with severity colour,
      json, markdown, self-contained html
- [x] 44 new tests

Decisions taken along the way:
- Every renderer has a distinct "Not checked" section, and the markdown and
  html ones say in words that these are not passes. The distinction only
  matters if it survives into the output someone actually reads.
- `--baseline` reports resolved findings as well as new ones. A scheduled
  audit that only ever reports new problems never tells you anything got
  better.
- Baseline files carry a format version and are refused rather than
  misread if it does not match.
- The JSON renderer routes through `Redactor`, like every other JSON path.
- `report` gets the audit *summary* only. The findings belong to `audit`,
  which can rank and filter them.
- The test harness now applies Thor's option defaults when constructing a
  command directly, which it previously did not — tests were seeing nil
  where a real invocation sees the declared default.

## Phase 7 — Supporting work

- [ ] `Formatter.findings` — severity-coloured grouped output, plus markdown
      and HTML emitters
- [ ] Extend `Anonymizer` with `ssid()`
- [ ] Record anonymized JSON fixtures per endpoint for check tests
- [ ] Value completion for `--check` / `--severity`
- [ ] README: audit section, check catalog, exit codes, config schema
- [ ] `--timeout` class option — 15+ endpoints at 30s each is a long worst case
