module UiManage
  # Rendering for the audit-oriented read commands. Kept out of CLI so the
  # command definitions there stay readable; every method here follows the
  # same shape as the older show_* helpers and is reused by `report`.
  #
  # Each of these reads an endpoint the controller may not serve, so they go
  # through #optional_data and print why a section is missing rather than
  # aborting the run.
  module AuditViews
    # Bands as UniFi names them on a radio.
    RADIO_BANDS = { 'ng' => '2.4 GHz', 'na' => '5 GHz', '6e' => '6 GHz', 'ax' => '6 GHz' }.freeze

    # Classification lives in WlanSecurity so the audit checks and this view
    # cannot drift apart about what counts as insecure.
    def wlan_security_label(wlan) = WlanSecurity.label(wlan)

    def insecure_wlan?(wlan) = WlanSecurity.insecure?(wlan)

    def show_wlans(client: nil, anon: Anonymizer.new(false))
      client ||= resolve_client
      wlans    = optional_data(:wlans, client: client, label: 'WLANs')
      return if wlans.nil?

      nets   = network_names(client)
      wlans  = wlans.select { |w| insecure_wlan?(w) } if options[:insecure_only]

      return Formatter.json(anon.deep_scrub(wlans)) if options[:json]

      if wlans.empty?
        say options[:insecure_only] ? 'No insecure WLANs found.' : 'No WLANs configured.'
        return
      end

      rows = wlans.map do |w|
        [
          anon.enabled? ? anon.scrub(w['name']) : w['name'],
          Formatter.enabled_badge(w['enabled']),
          wlan_security_label(w),
          (w['wpa_enc'] || '-').to_s.upcase,
          (w['pmf_mode'] || 'disabled').to_s,
          w['wps'] ? 'YES' : 'no',
          w['is_guest'] ? 'yes' : 'no',
          w['hide_ssid'] ? 'yes' : 'no',
          wlan_band_label(w),
          nets[w['networkconf_id']] || '-',
          passphrase_label(w, anon)
        ]
      end

      Formatter.table(
        ['SSID', 'Enabled', 'Security', 'Cipher', 'PMF', 'WPS', 'Guest', 'Hidden', 'Band', 'Network', 'Passphrase'],
        rows,
        title: "WLANs (#{rows.size})",
        sort:  options[:sort]
      )
    end

    def wlan_band_label(wlan)
      case wlan['wlan_band'].to_s
      when '2g' then '2.4 GHz'
      when '5g' then '5 GHz'
      when '6g' then '6 GHz'
      else 'all'
      end
    end

    # The passphrase itself is never printed. Its length is, because that is
    # what an audit needs — except under --anon, where the output is destined
    # for somewhere less private than this terminal.
    def passphrase_label(wlan, anon)
      psk = wlan['x_passphrase'].to_s
      return '-' if psk.empty?
      return 'set' if anon.enabled?

      "set (#{psk.length} chars)"
    end

    def show_settings(client: nil, anon: Anonymizer.new(false))
      settings = optional_data(:settings, client: client, label: 'Settings')
      return if settings.nil?

      settings = Redactor.scrub(settings)
      if (section = options[:section])
        settings = settings.select { |s| s['key'].to_s.downcase.include?(section.downcase) }
      end

      return Formatter.json(anon.deep_scrub(settings)) if options[:json]

      if settings.empty?
        say options[:section] ? "No settings section matches #{options[:section].inspect}." : 'No settings found.'
        return
      end

      rows = settings.flat_map do |section_hash|
        key = section_hash['key']
        section_hash.reject { |k, _| %w[key _id site_id].include?(k) }
                    .sort_by { |k, _| k }
                    .map { |field, value| [key, field, anon.scrub(compact_value(value))] }
      end

      Formatter.table(
        %w[Section Setting Value],
        rows,
        title: "Site Settings (#{settings.size} sections)",
        sort:  options[:sort]
      )
    end

    # Renders a value for a single table cell: nested structures collapse to
    # compact JSON, long strings are truncated.
    def compact_value(value, limit: 60)
      str = case value
            when Hash, Array then JSON.generate(value)
            when nil then '-'
            when true, false then value.to_s
            else value.to_s
            end
      str.length > limit ? "#{str[0, limit - 1]}…" : str
    end

    def show_health(client: nil, anon: Anonymizer.new(false))
      health = optional_data(:health, client: client, label: 'Health')
      return if health.nil?

      return Formatter.json(anon.deep_scrub(health)) if options[:json]

      if health.empty?
        say 'No health information reported.'
        return
      end

      rows = health.map do |h|
        [h['subsystem'], h['status'].to_s.upcase, anon.scrub(health_details(h))]
      end

      Formatter.table(
        %w[Subsystem Status Details],
        rows,
        title: 'Subsystem Health',
        sort:  options[:sort]
      )
    end

    # Each subsystem reports a different set of counters; this picks the ones
    # worth reading at a glance and skips the ones the controller left out.
    def health_details(entry)
      parts = []
      parts << "#{entry['num_user']} clients"            if entry['num_user']
      parts << "#{entry['num_guest']} guests"            if entry['num_guest'].to_i > 0
      parts << "#{entry['num_ap']} APs"                  if entry['num_ap']
      parts << "#{entry['num_sw']} switches"             if entry['num_sw']
      parts << "#{entry['num_gw']} gateways"             if entry['num_gw']
      parts << "#{entry['num_adopted']} adopted"         if entry['num_adopted']
      parts << "#{entry['num_disconnected']} disconnected" if entry['num_disconnected'].to_i > 0
      parts << "#{entry['num_pending']} pending"         if entry['num_pending'].to_i > 0
      parts << "WAN #{entry['wan_ip']}"                  if entry['wan_ip']
      parts << "#{entry['latency']}ms"                   if entry['latency']
      parts << "up #{format_uptime(entry['uptime'])}"    if entry['uptime']
      parts << "#{entry['drops']} drops"                 if entry['drops'].to_i > 0
      parts.empty? ? '-' : parts.join(', ')
    end

    def show_alarms(client: nil, anon: Anonymizer.new(false))
      alarms = optional_data(:alarms, client: client, label: 'Alarms',
                             within: window_hours, archived: !!options[:archived])
      return if alarms.nil?

      return Formatter.json(anon.deep_scrub(alarms)) if options[:json]

      if alarms.empty?
        say "No alarms in the last #{window_hours}h."
        return
      end

      rows = alarms.map do |a|
        [format_event_time(a), a['subsystem'] || '-', a['key'] || '-', anon.scrub(compact_value(a['msg'], limit: 80))]
      end

      Formatter.table(
        %w[Time Subsystem Key Message],
        rows,
        title: "Alarms, last #{window_hours}h (#{rows.size})",
        sort:  options[:sort]
      )
    end

    def show_events(client: nil, anon: Anonymizer.new(false))
      events = optional_data(:events, client: client, label: 'Events',
                             within: window_hours, limit: record_limit)
      return if events.nil?

      if (pattern = options[:type])
        needle = pattern.downcase
        events = events.select { |e| [e['key'], e['msg']].any? { |v| v.to_s.downcase.include?(needle) } }
      end

      return Formatter.json(anon.deep_scrub(events)) if options[:json]

      if events.empty?
        say options[:type] ? "No events match #{options[:type].inspect}." : "No events in the last #{window_hours}h."
        return
      end

      rows = events.map do |e|
        [format_event_time(e), e['subsystem'] || '-', e['key'] || '-', anon.scrub(compact_value(e['msg'], limit: 80))]
      end

      Formatter.table(
        %w[Time Subsystem Key Message],
        rows,
        title: "Events, last #{window_hours}h (#{rows.size})",
        sort:  options[:sort]
      )
    end

    def show_threats(client: nil, anon: Anonymizer.new(false))
      threats = optional_data(:threats, client: client, label: 'Threats',
                              endpoint: :ips_events,
                              within: window_hours, limit: record_limit)
      return if threats.nil?

      if (min = options[:severity])
        threats = threats.select { |t| threat_severity_rank(t) >= severity_rank(min) }
      end

      return Formatter.json(anon.deep_scrub(threats)) if options[:json]

      if threats.empty?
        say "No IDS/IPS detections in the last #{window_hours}h."
        return
      end

      rows = threats.map do |t|
        [
          format_event_time(t),
          threat_severity_label(t),
          t['catname'] || t['inner_alert_category'] || '-',
          anon.scrub(compact_value(t['inner_alert_signature'] || t['msg'], limit: 50)),
          anon.ip(t['src_ip'] || t['srcip']) || '-',
          anon.ip(t['dest_ip'] || t['dstip']) || '-',
          t['inner_alert_action'] || t['action'] || '-'
        ]
      end

      Formatter.table(
        %w[Time Severity Category Signature Source Destination Action],
        rows,
        title: "IDS/IPS Detections, last #{window_hours}h (#{rows.size})",
        sort:  options[:sort]
      )
    end

    # Suricata numbers severity 1 (most severe) to 3; the controller passes it
    # through unchanged. Inverted here so "higher rank is worse" holds.
    SEVERITY_NAMES = { 3 => 'low', 2 => 'medium', 1 => 'high' }.freeze

    def threat_severity_rank(threat)
      raw = threat['inner_alert_severity'] || threat['severity']
      return 0 unless raw

      4 - raw.to_i.clamp(1, 3)
    end

    def threat_severity_label(threat)
      raw = threat['inner_alert_severity'] || threat['severity']
      SEVERITY_NAMES[raw.to_i] || raw&.to_s || '-'
    end

    def severity_rank(name)
      { 'low' => 1, 'medium' => 2, 'high' => 3 }.fetch(name.to_s.downcase) do
        raise Thor::Error, "ERROR: unknown severity #{name.inspect} — use low, medium, or high."
      end
    end

    def show_admins(client: nil, anon: Anonymizer.new(false))
      admins = optional_data(:admins, client: client, label: 'Admins')
      return if admins.nil?

      return Formatter.json(anon.deep_scrub(admins)) if options[:json]

      if admins.empty?
        say 'No administrators reported.'
        return
      end

      rows = admins.map do |a|
        [
          anon.enabled? ? anon.scrub(a['name']) : a['name'],
          anon.enabled? ? 'redacted@example.com' : (a['email'] || '-'),
          a['role'] || (a['is_super'] ? 'super' : '-'),
          a['is_super'] ? 'YES' : 'no',
          two_factor_label(a),
          a['last_site_name'] || '-'
        ]
      end

      Formatter.table(
        ['Name', 'Email', 'Role', 'Super', '2FA', 'Last Site'],
        rows,
        title: "Administrators (#{rows.size})",
        sort:  options[:sort]
      )
    end

    # Which field carries the 2FA state depends on the controller version, and
    # some versions report none at all. "unknown" is the honest answer there —
    # an audit must not read a missing field as "no 2FA configured".
    TOTP_KEYS = %w[x_has_totp has_totp totp_enabled x_totp_secret].freeze

    def two_factor_label(admin)
      key = TOTP_KEYS.find { |k| admin.key?(k) }
      return 'unknown' unless key

      value = admin[key]
      value.nil? || value == false || value == '' ? 'no' : 'yes'
    end

    def show_rogue_aps(client: nil, anon: Anonymizer.new(false))
      client ||= resolve_client
      rogues   = optional_data(:rogue_aps, client: client, label: 'Rogue APs', within: window_hours)
      return if rogues.nil?

      if (floor = options[:min_signal])
        rogues = rogues.select { |r| (r['signal'] || r['rssi']).to_i >= floor.to_i }
      end

      return Formatter.json(anon.deep_scrub(rogues)) if options[:json]

      if rogues.empty?
        say "No neighbouring access points seen in the last #{window_hours}h."
        return
      end

      ours = our_ssids(client)

      rows = rogues.map do |r|
        essid = r['essid'].to_s
        [
          anon.enabled? ? anon.scrub(essid) : (essid.empty? ? '(hidden)' : essid),
          anon.mac(r['bssid']),
          r['channel'] || '-',
          RADIO_BANDS[r['radio'].to_s] || r['band'] || '-',
          r['signal'] || r['rssi'] ? "#{r['signal'] || r['rssi']} dBm" : '-',
          r['security'] || '-',
          impersonation_label(essid, ours),
          format_last_seen(r['last_seen'] || r['report_time'])
        ]
      end

      Formatter.table(
        ['SSID', 'BSSID', 'Channel', 'Band', 'Signal', 'Security', 'Ours?', 'Last Seen'],
        rows,
        title: "Neighbouring Access Points, last #{window_hours}h (#{rows.size})",
        sort:  options[:sort]
      )
    end

    # An unmanaged AP broadcasting one of our own SSIDs is the evil-twin
    # signal worth surfacing here. A nil set means WLANs could not be read, so
    # the question is unanswerable rather than answered "no".
    def impersonation_label(essid, ours)
      return '?' if ours.nil?
      return '-' if essid.to_s.empty?

      ours.include?(essid.downcase) ? 'IMPERSONATES' : 'no'
    end

    def our_ssids(client)
      wlans = client.optional(:wlans)
      wlans&.map { |w| w['name'].to_s.downcase }
    end

    def show_vpn(client: nil, anon: Anonymizer.new(false))
      nets = with_client(client) { |c| c.networks }
      vpns = nets.select { |n| vpn_network?(n) }

      return Formatter.json(anon.deep_scrub(vpns)) if options[:json]

      if vpns.empty?
        say 'No VPN networks configured.'
        return
      end

      rows = vpns.map do |n|
        [
          n['name'],
          n['vpn_type'] || n['purpose'],
          Formatter.enabled_badge(n['enabled'] != false),
          n['purpose'],
          anon.scrub(n['ip_subnet'] || n['vpn_client_default_route'] || '-'),
          vpn_auth_label(n)
        ]
      end

      Formatter.table(
        %w[Name Type Enabled Purpose Subnet Auth],
        rows,
        title: "VPN Networks (#{rows.size})",
        sort:  options[:sort]
      )
    end

    VPN_PURPOSES = %w[remote-user-vpn site-vpn vpn-client].freeze

    def vpn_network?(net)
      VPN_PURPOSES.include?(net['purpose'].to_s) || !net['vpn_type'].to_s.empty?
    end

    # Names the authentication method without echoing the material itself.
    def vpn_auth_label(net)
      parts = []
      parts << 'pre-shared key' unless net['x_ipsec_pre_shared_key'].to_s.empty?
      parts << 'RADIUS'         unless net['radiusprofile_id'].to_s.empty?
      parts << 'local users'    if net['require_mschapv2'] || net['purpose'] == 'remote-user-vpn' && parts.empty?
      parts << 'WireGuard keys' unless net['wireguard_public_key'].to_s.empty?
      parts.empty? ? '-' : parts.join(' + ')
    end

    def show_vlans(client: nil, anon: Anonymizer.new(false))
      nets = with_client(client) { |c| c.networks }
      nets = nets.reject { |n| n['purpose'] == 'wan' } unless options[:all]

      return Formatter.json(anon.deep_scrub(nets)) if options[:json]

      if nets.empty?
        say 'No networks configured.'
        return
      end

      rows = nets.map do |n|
        [
          n['name'],
          n['vlan'] || (n['vlan_enabled'] == false ? 'untagged' : '-'),
          anon.scrub(n['ip_subnet'] || '-'),
          n['purpose'] || '-',
          Formatter.enabled_badge(n['enabled'] != false),
          n['dhcpd_enabled'] ? 'yes' : 'no',
          isolation_label(n),
          n['internet_access_enabled'] == false ? 'no' : 'yes'
        ]
      end

      Formatter.table(
        ['Name', 'VLAN', 'Subnet', 'Purpose', 'Enabled', 'DHCP', 'Isolated', 'Internet'],
        rows,
        title: "Networks / VLANs (#{rows.size})",
        sort:  options[:sort]
      )
    end

    def isolation_label(net)
      return 'yes' if net['network_isolation_enabled'] || net['is_guest']

      'no'
    end

    def show_routes(client: nil, anon: Anonymizer.new(false))
      client ||= resolve_client
      routes   = optional_data(:routes, client: client, label: 'Static routes')

      if options[:json]
        ddns_json = client.optional(:dynamic_dns)
        return Formatter.json(anon.deep_scrub('static_routes' => routes, 'dynamic_dns' => ddns_json))
      end

      if routes.nil?
        # optional_data already said why.
      elsif routes.empty?
        say 'No static routes configured.'
      else
        rows = routes.map do |r|
          [
            r['name'],
            Formatter.enabled_badge(r['enabled']),
            anon.scrub(r['static-route_network'] || '-'),
            anon.scrub(r['static-route_nexthop'] || r['static-route_interface'] || '-'),
            r['static-route_distance'] || '-',
            r['static-route_type'] || '-'
          ]
        end

        Formatter.table(
          %w[Name Enabled Network NextHop Distance Type],
          rows,
          title: "Static Routes (#{rows.size})",
          sort:  options[:sort]
        )
      end

      show_dynamic_dns(client: client, anon: anon)
    end

    def show_dynamic_dns(client: nil, anon: Anonymizer.new(false))
      entries = optional_data(:dynamic_dns, client: client, label: 'Dynamic DNS')
      return if entries.nil?

      if entries.empty?
        say 'No dynamic DNS entries configured.'
        return
      end

      rows = entries.map do |d|
        [
          d['service'] || '-',
          anon.enabled? ? anon.scrub(d['host_name'].to_s) : (d['host_name'] || '-'),
          d['interface'] || '-',
          d['login'].to_s.empty? ? '-' : 'set',
          d['x_password'].to_s.empty? ? 'not set' : 'set'
        ]
      end

      Formatter.table(
        %w[Service Hostname Interface Username Password],
        rows,
        title: "Dynamic DNS (#{rows.size})",
        sort:  options[:sort]
      )
    end

    def show_firmware(client: nil, anon: Anonymizer.new(false))
      devs = with_client(client) { |c| c.devices }
      devs = devs.select { |d| d['upgradable'] } if options[:outdated]

      return Formatter.json(anon.deep_scrub(devs)) if options[:json]

      if devs.empty?
        say options[:outdated] ? 'Every device is on its latest available firmware.' : 'No devices found.'
        return
      end

      rows = devs.map do |d|
        [
          anon.enabled? ? anon.scrub(d['name'].to_s) : (d['name'] || d['model']),
          d['model'] || '-',
          d['version'] || '-',
          d['upgrade_to_firmware'] || '-',
          d['upgradable'] ? 'YES' : 'no',
          device_state_label(d)
        ]
      end

      Formatter.table(
        ['Device', 'Model', 'Version', 'Available', 'Update', 'State'],
        rows,
        title: "Firmware (#{rows.size} devices)",
        sort:  options[:sort]
      )
    end

    # Naming lives in DeviceState so the audit checks agree with this view.
    def device_state_label(device) = DeviceState.label(device)

    def show_wifi_experience(client: nil, anon: Anonymizer.new(false))
      sta = with_client(client) { |c| c.clients }.reject { |c| c['is_wired'] }

      if (floor = options[:signal_below])
        sta = sta.select { |c| c['signal'].to_i < floor.to_i }
      end

      return Formatter.json(anon.deep_scrub(sta)) if options[:json]

      if sta.empty?
        say options[:signal_below] ? "No wireless clients below #{options[:signal_below]} dBm." : 'No wireless clients connected.'
        return
      end

      rows = sta.sort_by { |c| c['signal'].to_i }.map do |c|
        [
          anon.enabled? ? anon.scrub(c['name'] || c['hostname'] || '—') : (c['name'] || c['hostname'] || '—'),
          anon.enabled? ? anon.scrub(c['essid'].to_s) : (c['essid'] || '-'),
          RADIO_BANDS[c['radio'].to_s] || c['radio'] || '-',
          c['channel'] || '-',
          c['signal'] ? "#{c['signal']} dBm" : '-',
          c['noise'] ? "#{c['noise']} dBm" : '-',
          snr_label(c),
          retry_label(c),
          c['satisfaction'] ? "#{c['satisfaction']}%" : '-',
          "#{format_speed(c['tx_rate'].to_i / 1000)} / #{format_speed(c['rx_rate'].to_i / 1000)}"
        ]
      end

      Formatter.table(
        ['Client', 'SSID', 'Band', 'Ch', 'Signal', 'Noise', 'SNR', 'Retries', 'Satisfaction', 'TX / RX'],
        rows,
        title: "Wireless Experience (#{rows.size} clients)",
        sort:  options[:sort]
      )
    end

    # Signal-to-noise margin in dB. Both figures are negative dBm, so the
    # margin is the difference between them.
    def snr_label(client)
      signal = client['signal']
      noise  = client['noise']
      return '-' unless signal && noise

      "#{signal.to_i - noise.to_i} dB"
    end

    def retry_label(client)
      attempts = client['wifi_tx_attempts'].to_i
      retries  = client['wifi_tx_retries'].to_i
      return '-' if attempts.zero?

      "#{(retries.to_f / attempts * 100).round(1)}%"
    end

    def show_port_errors(client: nil, anon: Anonymizer.new(false))
      devs = with_client(client) { |c| c.devices }

      rows_data = devs.flat_map do |d|
        Array(d['port_table']).map { |p| [d, p] }
      end
      rows_data = rows_data.select { |_, p| port_has_errors?(p) } unless options[:all]

      if options[:json]
        payload = rows_data.map { |d, p| { 'device' => d['name'], 'port' => p } }
        return Formatter.json(anon.deep_scrub(payload))
      end

      if rows_data.empty?
        say options[:all] ? 'No ports found.' : 'No ports reporting errors or drops.'
        return
      end

      rows = rows_data.map do |d, p|
        [
          anon.enabled? ? anon.scrub(d['name'].to_s) : (d['name'] || d['model']),
          p['port_idx'],
          p['name'] || '-',
          p['up'] ? 'up' : 'down',
          format_speed(p['speed']),
          p['full_duplex'] == false && p['up'] ? 'half' : 'full',
          p['rx_errors'].to_i,
          p['tx_errors'].to_i,
          p['rx_dropped'].to_i,
          p['tx_dropped'].to_i
        ]
      end

      Formatter.table(
        ['Device', 'Port', 'Name', 'Link', 'Speed', 'Duplex', 'RX Err', 'TX Err', 'RX Drop', 'TX Drop'],
        rows,
        title: "Port Errors (#{rows.size} ports)",
        sort:  options[:sort]
      )
    end

    ERROR_COUNTERS = %w[rx_errors tx_errors rx_dropped tx_dropped].freeze

    # Half duplex on a live link is counted as a fault: it is almost always a
    # failed autonegotiation rather than a deliberate setting.
    def port_has_errors?(port)
      ERROR_COUNTERS.any? { |k| port[k].to_i > 0 } ||
        (port['up'] && port['full_duplex'] == false)
    end

    private

    # `report` runs these helpers outside their own commands, where those
    # commands' options are not in scope. Both fall back to the same defaults
    # the options declare, so a windowed view means the same thing either way.
    DEFAULT_WINDOW_HOURS = 24
    DEFAULT_RECORD_LIMIT = 500

    def window_hours = options[:within] || DEFAULT_WINDOW_HOURS

    def record_limit = options[:limit] || DEFAULT_RECORD_LIMIT

    # Reads an endpoint the controller may not provide. On refusal, prints why
    # and returns nil — the same degradation the audit applies, rather than
    # ending a report halfway through.
    def optional_data(name, client: nil, label: nil, endpoint: nil, **args)
      client ||= resolve_client
      key      = endpoint || name
      data     = with_client(client) { |c| c.optional(key, **args) }
      return data unless data.nil?

      Formatter.unavailable(label || name.to_s, client.degradations[key])
      nil
    end

    # Network id => display name, for resolving the network a WLAN belongs to.
    def network_names(client)
      with_client(client) { |c| c.networks }
        .each_with_object({}) { |n, h| h[n['_id']] = n['vlan'] ? "#{n['name']} (VLAN #{n['vlan']})" : n['name'] }
    end

    # Alarms and events carry either an epoch `time` in milliseconds or a
    # preformatted `datetime`, depending on endpoint and version.
    def format_event_time(entry)
      if (ms = entry['time'])
        Time.at(ms.to_i / 1000).strftime('%Y-%m-%d %H:%M')
      elsif (dt = entry['datetime'])
        dt.to_s.sub('T', ' ').sub(/Z\z/, '')
      else
        '-'
      end
    end
  end
end
