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

## Phase 3 — Check engine (`lib/ui_manage/audit/`)

- [ ] `Audit::Check` — id, title, category, severity, `#run(context)`,
      remediation text
- [ ] `Audit::Finding` — check id, severity, subject, message, evidence,
      remediation
- [ ] `Audit::Context` — lazily fetches and caches every endpoint, shared
      across checks; carries `client.degradations`
- [ ] `Audit::Registry` — auto-loads `checks/*.rb`, filterable by id/category/
      severity
- [ ] Three result states, not two: pass / fail / **skipped** (endpoint
      unavailable) — wired to Phase 1's degradation reporting
- [ ] Severity ladder: critical / high / medium / low / info
- [ ] Thresholds in `~/.config/ui-manage/audit.toml` with built-in defaults
      (CPU %, memory %, temp, RSSI floor, PSK min length, sensitive ports)
- [ ] Suppression list so accepted risks stop reappearing

---

## Phase 4 — Security checks

**Wireless**
- [ ] Open / WEP / WPA1 / TKIP SSID — critical
- [ ] PSK shorter than threshold, or known-weak/default — high
- [ ] WPS enabled — high
- [ ] PMF disabled on a WPA3-capable SSID — medium
- [ ] Guest SSID without guest policy / L2 isolation — high
- [ ] Guest network able to reach RFC1918 LAN ranges — critical
- [ ] SSID broadcasting on the management VLAN — high
- [ ] Rogue AP advertising one of our SSIDs (evil twin) — critical

**Perimeter**
- [ ] Port forward exposing a sensitive port (22/23/445/3389/5900/1433/3306/
      5432/27017/6379/9200) — critical
- [ ] Port forward with source `any` — high
- [ ] Port forward targeting the gateway/controller itself — critical
- [ ] UPnP enabled — high
- [ ] Remote/cloud access disagreeing with `policy --remote-access` — medium
- [ ] WAN-facing management (SSH/HTTPS reachable from WAN) — critical
- [ ] DDNS credentials stored in cleartext — low

**Firewall**
- [ ] `WAN_IN` default-accept, or any accept-any-any rule — critical
- [ ] Disabled security-relevant rules — medium
- [ ] Drop/reject rules with logging off — low
- [ ] No inter-VLAN restriction between IoT/guest and trusted VLANs — high
- [ ] Firewall groups referenced by no rule — info

**Access control**
- [ ] Admin without 2FA — high
- [ ] More than N super-admins — medium
- [ ] Admin idle >90 days — medium
- [ ] Device SSH enabled — medium; SSH password auth rather than keys — high
- [ ] Default/shared device SSH credentials — critical
- [ ] SNMP v1/v2c enabled, or community `public` — high
- [ ] Weak/default RADIUS shared secret — high

**Threat posture**
- [ ] IDS/IPS disabled or detect-only — high
- [ ] IPS signature set stale — medium
- [ ] Unacknowledged IPS detections in the last 24h — high
- [ ] Auto firmware updates disabled — medium
- [ ] Firmware with a known advisory — critical (needs a bundled advisory list)
- [ ] Controller TLS unverified (reuse per-device `verify_ssl`) — medium

**Network hygiene**
- [ ] Unknown/unnamed client on a trusted VLAN — medium
- [ ] IoT-OUI client on the default VLAN — low
- [ ] Untrusted port without 802.1X or isolation — medium
- [ ] Unadopted or pending-adoption device — high

---

## Phase 5 — Health checks

- [ ] Device offline / disconnected / adopting — critical
- [ ] Firmware update available — medium
- [ ] CPU, memory, temperature over threshold — high
- [ ] Storage over threshold — high
- [ ] Uptime under 1h (unexpected reboot) — medium
- [ ] WAN down or failover active — critical
- [ ] WAN latency / packet loss over threshold — high
- [ ] Port errors/CRC/drops climbing — medium
- [ ] Port speed or duplex mismatch — medium
- [ ] PoE draw near budget — high
- [ ] DHCP pool >85% utilized — high
- [ ] Overlapping subnets, or a reservation outside its pool — high
- [ ] Duplicate static IP / reservation collisions — high
- [ ] Clients below RSSI floor, or with high TX-retry % — medium
- [ ] Own-AP channel overlap / co-channel interference — medium
- [ ] Channel utilization over threshold — medium
- [ ] NTP unsynchronized — medium
- [ ] Site backup older than N days — high
- [ ] Alarm count spike vs the 7-day baseline — medium

---

## Phase 6 — `audit` command

- [ ] `audit [CATEGORY]` — all / `health` / `security`
- [ ] `--severity LEVEL` — report at or above
- [ ] `--fail-on LEVEL` — exit code (0 clean / 1 findings / 2 error) for cron and CI
- [ ] `--format table|json|markdown|html`
- [ ] `--check ID` / `--skip ID` (repeatable, glob-friendly)
- [ ] `--list-checks`, `--explain ID`, `--summary`, `--all`
- [ ] `--anon` throughout
- [ ] `--output FILE`
- [ ] `--baseline save FILE` / `--baseline FILE` — diff against a known-good
      snapshot; this is what turns it into ongoing monitoring
- [ ] `--remediate` — print the UniFi UI path or API call per finding
- [ ] Put `audit` in its own tier in `sort_commands!`
- [ ] Fold an audit summary into `report`

---

## Phase 7 — Supporting work

- [ ] `Formatter.findings` — severity-coloured grouped output, plus markdown
      and HTML emitters
- [ ] Extend `Anonymizer` with `ssid()`
- [ ] Record anonymized JSON fixtures per endpoint for check tests
- [ ] Value completion for `--check` / `--severity`
- [ ] README: audit section, check catalog, exit codes, config schema
- [ ] `--timeout` class option — 15+ endpoints at 30s each is a long worst case
