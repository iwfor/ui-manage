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
          anon.ssid(w['name']),
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

      log_table(alarms, anon, title: "Alarms, last #{window_hours}h (#{alarms.size})")
    end

    def show_events(client: nil, anon: Anonymizer.new(false))
      events = optional_data(:events, client: client, label: 'Events',
                             within: window_hours, limit: record_limit)
      return if events.nil?

      if (pattern = options[:type])
        needle = pattern.downcase
        events = events.select do |e|
          [SystemLog.key(e), SystemLog.title(e), SystemLog.message(e)].any? { |v| v.to_s.downcase.include?(needle) }
        end
      end

      return Formatter.json(anon.deep_scrub(events)) if options[:json]

      if events.empty?
        say options[:type] ? "No events match #{options[:type].inspect}." : "No events in the last #{window_hours}h."
        return
      end

      log_table(events, anon, title: "Events, last #{window_hours}h (#{events.size})")
    end

    def show_threats(client: nil, anon: Anonymizer.new(false))
      threats = optional_data(:threats, client: client, label: 'Threats',
                              endpoint: :ips_events,
                              within: window_hours, limit: record_limit)
      return if threats.nil?

      if (min = options[:severity])
        threats = threats.select { |t| SystemLog.rank(t) >= severity_rank(min) }
      end

      return Formatter.json(anon.deep_scrub(threats)) if options[:json]

      if threats.empty?
        say "No IDS/IPS detections in the last #{window_hours}h."
        return
      end

      log_table(threats, anon, title: "IDS/IPS Detections, last #{window_hours}h (#{threats.size})")
    end

    def severity_rank(name)
      SystemLog::RANKS.fetch(name.to_s.downcase) do
        raise Thor::Error, "ERROR: unknown severity #{name.inspect} — use #{SystemLog::RANKS.keys.join(', ')}."
      end
    end

    # Alarms, events, and detections are all system-log entries, so one
    # table renders all three. Reading the fields lives in SystemLog, which
    # also knows the legacy shapes an older controller still returns.
    def log_table(entries, anon, title:)
      rows = entries.map do |e|
        [
          format_event_time(e),
          SystemLog.severity(e) || '-',
          SystemLog.category(e) || '-',
          anon.scrub(compact_value(SystemLog.title(e), limit: 40)),
          anon.scrub(compact_value(SystemLog.message(e), limit: 80))
        ]
      end

      Formatter.table(%w[Time Severity Category Title Message], rows, title: title, sort: options[:sort])
    end

    def show_admins(client: nil, anon: Anonymizer.new(false))
      client ||= resolve_client
      admins   = optional_data(:admins, client: client, label: 'Admins')
      return if admins.nil?

      if options[:json]
        # Names and addresses have no shape to recognise, so they are
        # registered first and deep_scrub replaces them wherever they appear.
        admins.each { |a| anon.person(AdminAccount.name(a)) && anon.email(a['email']) }
        return Formatter.json(anon.deep_scrub(admins))
      end

      if admins.empty?
        say 'No administrators reported.'
        return
      end

      rows = admins.map do |a|
        [
          anon.person(AdminAccount.name(a)),
          anon.email(a['email']) || '-',
          AdminAccount.role(a, site: client.site) || '-',
          AdminAccount.super?(a) ? 'YES' : 'no',
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

    # Reading lives in AdminAccount so the audit check agrees with this view,
    # including that "unknown" is distinct from "no".
    def two_factor_label(admin) = AdminAccount.two_factor(admin).to_s

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
          essid.empty? ? '(hidden)' : anon.ssid(essid),
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

      WlanSecurity.impersonates?(essid, ours) ? 'IMPERSONATES' : 'no'
    end

    def our_ssids(client)
      wlans = client.optional(:wlans)
      wlans && WlanSecurity.ssid_names(wlans)
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
      client ||= resolve_client
      nets, zones = with_client(client) { |c| [c.networks, c.optional(:firewall_zones)] }
      nets = nets.reject { |n| n['purpose'] == 'wan' } unless options[:all]

      return Formatter.json(anon.deep_scrub(nets)) if options[:json]

      if nets.empty?
        say 'No networks configured.'
        return
      end

      zone_names = zone_names_by_network(zones)
      rows = nets.map do |n|
        [
          n['name'],
          n['vlan'] || (n['vlan_enabled'] == false ? 'untagged' : '-'),
          anon.scrub(n['ip_subnet'] || '-'),
          n['purpose'] || '-',
          zone_names[n['_id']] || '-',
          Formatter.enabled_badge(n['enabled'] != false),
          n['dhcpd_enabled'] ? 'yes' : 'no',
          isolation_label(n),
          n['internet_access_enabled'] == false ? 'no' : 'yes'
        ]
      end

      Formatter.table(
        ['Name', 'VLAN', 'Subnet', 'Purpose', 'Zone', 'Enabled', 'DHCP', 'Isolated', 'Internet'],
        rows,
        title: "Networks / VLANs (#{rows.size})",
        sort:  options[:sort]
      )
    end

    # network id => zone name. Empty when the controller has no zones
    # (before Network 9), so the column reads "-" rather than failing.
    def zone_names_by_network(zones)
      FirewallZone.by_network(zones).transform_values { |z| z['name'] }
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
          anon.label(d['host_name']) || '-',
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
          anon.device_name(d['name'] || d['model']),
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
          anon.device_name(c['name'] || c['hostname']) || '—',
          anon.ssid(c['essid']) || '-',
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
          anon.device_name(d['name'] || d['model']),
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

    def format_event_time(entry)
      time = SystemLog.time(entry)
      time ? time.strftime('%Y-%m-%d %H:%M') : '-'
    end
  end
end
