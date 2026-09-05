require 'ipaddr'

module UiManage
  # The commands that change the controller: networks (VLANs), the clients
  # pinned to them and the addresses reserved for them, and wireless network
  # settings. Kept out of CLI like AuditViews, so cli.rb holds the command
  # definitions and this holds what they do.
  #
  # Every action resolves its target by name first and refuses on ambiguity
  # — a write that lands on the wrong network is worse than one that asks
  # for a more specific name. Validation of the values themselves lives in
  # NetworkConfig and WlanConfig.
  module ManageActions
    # --- networks / VLANs -----------------------------------------------------

    def create_vlan(name)
      client = resolve_client
      with_client(client) do |c|
        nets = c.networks
        abort "A network named #{name.inspect} already exists." if nets.any? { |n| n['name'] == name }
        if (taken = nets.find { |n| n['vlan'] && n['vlan'].to_i == options[:vlan].to_i })
          abort "VLAN #{options[:vlan]} is already used by '#{taken['name']}'."
        end

        zones   = c.optional(:firewall_zones)
        zone    = choose_zone(zones, options[:zone], guest: options[:guest])
        purpose = options[:purpose] || (options[:guest] && zones.nil? ? 'guest' : 'corporate')

        # A guest network is not also isolated: the Hotspot zone (or the
        # legacy guest purpose) already keeps it from the LAN, and the
        # controller rejects "Isolate Network" on a non-corporate network.
        attrs = NetworkConfig.build(
          name:       name,
          vlan:       options[:vlan],
          subnet:     options[:subnet],
          purpose:    purpose,
          dhcp:       options[:dhcp],
          dhcp_range: options[:dhcp_range],
          isolate:    options[:isolate],
          internet:   options[:internet],
          zone_id:    zone && zone['_id']
        )

        net = c.create_network(attrs) || attrs
        say "Created network '#{net['name']}' (VLAN #{net['vlan']}, #{net['ip_subnet']})#{zone_suffix(zone)}."
        say "DHCP: #{net['dhcpd_enabled'] ? "#{net['dhcpd_start']}-#{net['dhcpd_stop']}" : 'off'}; " \
            "isolated: #{net['network_isolation_enabled'] ? 'yes' : 'no'}; " \
            "internet: #{net['internet_access_enabled'] == false ? 'no' : 'yes'}."
      end
    rescue NetworkConfig::Invalid => e
      abort "Error: #{e.message}"
    end

    def update_vlan(name)
      client = resolve_client
      with_client(client) do |c|
        net   = find_network(c.networks, name)
        zones = options[:zone] && c.optional(:firewall_zones)
        zone  = options[:zone] && choose_zone(zones, options[:zone], guest: false)

        attrs = NetworkConfig.attributes(
          name:       options[:rename],
          vlan:       options[:vlan],
          subnet:     options[:subnet],
          purpose:    options[:purpose],
          dhcp:       options[:dhcp],
          dhcp_range: options[:dhcp_range],
          isolate:    options[:isolate],
          internet:   options[:internet],
          zone_id:    zone && zone['_id']
        )
        if options[:dhcp_range] && options[:subnet].nil?
          attrs['dhcpd_start'], attrs['dhcpd_stop'] = NetworkConfig.range_for(options[:dhcp_range], net['ip_subnet'])
        end
        abort 'Nothing to change — give at least one setting to set.' if attrs.empty?

        if attrs['vlan'] && (taken = c.networks.find { |n| n['_id'] != net['_id'] && n['vlan'].to_i == attrs['vlan'] })
          abort "VLAN #{attrs['vlan']} is already used by '#{taken['name']}'."
        end

        c.update_network(net['_id'], attrs)
        say "Updated network '#{net['name']}':"
        describe_network_change(attrs, zone).each { |line| say "  #{line}" }
      end
    rescue NetworkConfig::Invalid => e
      abort "Error: #{e.message}"
    end

    def delete_vlan(name)
      client = resolve_client
      with_client(client) do |c|
        net = find_network(c.networks, name)
        abort "'#{net['name']}' is a built-in network and cannot be deleted." if net['attr_no_delete']

        in_use = network_references(c, net['_id'])
        unless in_use.empty?
          abort "'#{net['name']}' is still in use — move these first:\n  #{in_use.join("\n  ")}"
        end

        unless options[:yes]
          abort "Refusing to delete '#{net['name']}' without --yes on a non-interactive terminal." unless $stdin.tty?
          return say('Nothing deleted.') unless yes?("Delete network '#{net['name']}' (VLAN #{net['vlan'] || 'untagged'}, #{net['ip_subnet']})? [y/N]")
        end

        c.delete_network(net['_id'])
        say "Deleted network '#{net['name']}'."
      end
    end

    # --- pinning clients to a VLAN --------------------------------------------

    def show_pins(client: nil, anon: Anonymizer.new(false))
      client ||= resolve_client
      known, nets = with_client(client) { |c| [c.known_clients, c.networks] }
      pinned = known.select { |u| u['virtual_network_override_enabled'] }

      return Formatter.json(anon.deep_scrub(pinned)) if options[:json]

      if pinned.empty?
        say 'No clients are pinned to a network. Use `ui-manage pin CLIENT --vlan N` to pin one.'
        return
      end

      names = network_names_by_id(nets)
      rows  = pinned.map do |u|
        [
          anon.device_name(u['name'] || u['hostname']) || '—',
          anon.mac(u['mac']),
          u['is_wired'] ? 'wired' : 'wireless',
          names[u['virtual_network_override_id']] || "unknown (#{u['virtual_network_override_id']})",
          anon.ip(u['last_ip']) || '—',
          format_last_seen(u['last_seen'])
        ]
      end

      Formatter.table(['Name', 'MAC', 'Type', 'Pinned To', 'Last IP', 'Last Seen'], rows,
                      title: "Pinned Clients (#{rows.size})", sort: options[:sort])
    end

    def pin_client(pattern)
      abort 'Give the target as --vlan N or --network NAME.' if options[:vlan].nil? && options[:network].nil?
      abort 'Use either --vlan or --network, not both.' if options[:vlan] && options[:network]

      client = resolve_client
      with_client(client) do |c|
        user = find_known_client(c.known_clients, pattern)
        net  = options[:vlan] ? find_network_by_vlan(c.networks, options[:vlan]) : find_network(c.networks, options[:network])

        c.update_known_client(user['_id'], 'virtual_network_override_enabled' => true,
                                           'virtual_network_override_id'      => net['_id'])

        label = client_label(user)
        say "Pinned #{label} to '#{net['name']}'#{net['vlan'] ? " (VLAN #{net['vlan']})" : ''}."
        say 'It takes effect the next time the client connects.'
        if user['is_wired']
          say 'Note: a wired client only lands on the VLAN if its switch port carries that VLAN (a trunk or "all" port profile).'
        end
      end
    end

    def unpin_client(pattern)
      client = resolve_client
      with_client(client) do |c|
        user = find_known_client(c.known_clients, pattern)
        unless user['virtual_network_override_enabled']
          say "#{client_label(user)} is not pinned to a network."
          return
        end

        c.update_known_client(user['_id'], 'virtual_network_override_enabled' => false,
                                           'virtual_network_override_id'      => '')
        say "Unpinned #{client_label(user)}; it will use the network of whatever it connects through."
      end
    end

    # --- static DHCP reservations ---------------------------------------------

    def reserve_client(pattern, address)
      client = resolve_client
      with_client(client) do |c|
        ip   = NetworkConfig.ipv4(address, what: 'IP address')
        user = find_known_client(c.known_clients, pattern)
        net  = network_for_address(c.networks, ip)

        if user['use_fixedip'] && user['fixed_ip'] == ip.to_s && user['network_id'] == net['_id']
          say "#{client_label(user)} already reserves #{ip}."
          return
        end
        refuse_unavailable_address(c.known_clients, user, ip, net)

        c.update_known_client(user['_id'], 'use_fixedip' => true,
                                           'fixed_ip'    => ip.to_s,
                                           'network_id'  => net['_id'])

        was = user['use_fixedip'] && user['fixed_ip']
        say "Reserved #{ip} for #{client_label(user)} on '#{net['name']}'#{was ? " (was #{was})" : ''}."
        say 'The client keeps its current address until its lease expires — reconnect it to take the new one now.'
        if (holder = dynamic_holder(c.known_clients, user, ip))
          say "Note: #{client_label(holder)} currently holds #{ip} on a dynamic lease; " \
              'the two collide until that lease is released.'
        end
      end
    rescue NetworkConfig::Invalid => e
      abort "Error: #{e.message}"
    end

    def unreserve_client(pattern)
      client = resolve_client
      with_client(client) do |c|
        user = find_known_client(c.known_clients, pattern)
        unless user['use_fixedip']
          say "#{client_label(user)} has no reserved address."
          return
        end

        # Only the switch is cleared, as the controller's own UI does: the
        # address stays on the record, so re-reserving it is one flag away,
        # and nothing reads `fixed_ip` without `use_fixedip` beside it.
        c.update_known_client(user['_id'], 'use_fixedip' => false)
        say "Released #{user['fixed_ip']} from #{client_label(user)}; " \
            'it takes an address from the DHCP pool from its next lease.'
      end
    end

    # --- wireless networks ----------------------------------------------------

    def update_wlan(ssid)
      client = resolve_client
      with_client(client) do |c|
        wlans = c.optional(:wlans)
        abort "WLANs: unavailable — #{c.degradations[:wlans]}" if wlans.nil?

        wlan = find_wlan(wlans, ssid)
        net  = options[:network] && find_network(c.networks, options[:network])

        attrs = WlanConfig.attributes(
          name:       options[:rename],
          network_id: net && net['_id'],
          guest:      options[:guest],
          isolate:    options[:isolate],
          pmf:        options[:pmf],
          hidden:     options[:hidden],
          enabled:    options[:enabled],
          band:       options[:band],
          security:   options[:security],
          passphrase: options[:passphrase] && read_secret(options[:passphrase], prompt: 'Passphrase: ')
        )
        abort 'Nothing to change — give at least one setting to set.' if attrs.empty?

        if attrs['security'] == 'open' && !attrs.key?('x_passphrase')
          attrs['x_passphrase'] = ''
        end

        c.update_wlan(wlan['_id'], attrs)
        say "Updated WLAN '#{wlan['name']}':"
        say "  network: #{net['name']}#{net['vlan'] ? " (VLAN #{net['vlan']})" : ''}" if net
        WlanConfig.describe(attrs).each { |line| say "  #{line}" }
      end
    rescue WlanConfig::Invalid => e
      abort "Error: #{e.message}"
    end

    private

    # --- lookups --------------------------------------------------------------

    # A LAN network by its full name, or by a substring of it if exactly one
    # matches. WAN networks are never candidates: nothing here should touch
    # them by accident.
    def find_network(nets, pattern)
      candidates = nets.reject { |n| n['purpose'] == 'wan' }
      unique_match(candidates, pattern, what: 'network') { |n| n['name'] }
    end

    def find_network_by_vlan(nets, vlan)
      id  = Integer(vlan, exception: false)
      abort "VLAN #{vlan.inspect} is not a number." unless id

      net = nets.find { |n| n['purpose'] != 'wan' && (n['vlan'] ? n['vlan'].to_i == id : id.zero?) }
      abort "No network uses VLAN #{id}. Run `ui-manage vlans` to see them." unless net
      net
    end

    # The LAN network a reserved address belongs to: the one whose subnet
    # contains it, since the controller stores a reservation against a
    # network. --network names one when the address is inside more than one.
    def network_for_address(nets, ip)
      if options[:network]
        net = find_network(nets, options[:network])
        subnet = subnet_of(net)
        abort "#{ip} is outside '#{net['name']}' (#{net['ip_subnet']})." unless subnet&.include?(ip)
        return net
      end

      matches = nets.select { |n| n['purpose'] != 'wan' && subnet_of(n)&.include?(ip) }
      case matches.size
      when 0 then abort "#{ip} is not inside any of your networks. Run `ui-manage vlans` to see their subnets."
      when 1 then matches.first
      else
        names = matches.map { |n| n['name'] }.join(', ')
        abort "#{ip} is inside more than one network (#{names}) — name one with --network."
      end
    end

    # An address the network cannot hand out, or has already promised to
    # someone else. Refused before the write, like every other refusal here.
    def refuse_unavailable_address(known, user, ip, net)
      gateway = net['ip_subnet'].to_s.split('/').first
      abort "#{ip} is the gateway address of '#{net['name']}'." if ip.to_s == gateway

      if (subnet = subnet_of(net))
        range = subnet.to_range
        abort "#{ip} is the network address of #{net['ip_subnet']}."   if ip == range.first && range.first != range.last
        abort "#{ip} is the broadcast address of #{net['ip_subnet']}." if ip == range.last  && range.first != range.last
      end

      taken = known.find { |u| u['_id'] != user['_id'] && u['use_fixedip'] && u['fixed_ip'] == ip.to_s }
      abort "#{ip} is already reserved for #{client_label(taken)}." if taken
    end

    # Another client sitting on the address right now, from the leases the
    # controller reports — a collision the reservation will not resolve on
    # its own, so it is worth saying rather than refusing.
    def dynamic_holder(known, user, ip)
      known.find { |u| u['_id'] != user['_id'] && !u['use_fixedip'] && u['ip'] == ip.to_s }
    end

    def subnet_of(net)
      IPAddr.new(net['ip_subnet'] || net['subnet'] || '')
    rescue IPAddr::Error
      nil
    end

    def find_wlan(wlans, pattern)
      unique_match(wlans, pattern, what: 'WLAN') { |w| w['name'] }
    end

    # A known client by name, hostname, MAC, or last IP. MAC and IP match
    # exactly; names match in full or as a unique substring.
    def find_known_client(known, pattern)
      needle = pattern.to_s.downcase
      exact  = known.find do |u|
        [u['mac'], u['last_ip'], u['fixed_ip'], u['name'], u['hostname']].any? { |v| v.to_s.downcase == needle }
      end
      return exact if exact

      unique_match(known, pattern, what: 'client') { |u| [u['name'], u['hostname']].compact.join(' / ') }
    end

    def unique_match(items, pattern, what:)
      needle = pattern.to_s.downcase
      exact  = items.find { |i| yield(i).to_s.downcase == needle }
      return exact if exact

      matches = items.select { |i| yield(i).to_s.downcase.include?(needle) }
      case matches.size
      when 0 then abort "No #{what} matches #{pattern.inspect}."
      when 1 then matches.first
      else
        names = matches.map { |i| yield(i) }.join(', ')
        abort "#{pattern.inspect} matches multiple #{what}s (#{names}) — use a more specific name."
      end
    end

    # The firewall zone a network should land in. --zone names one; --guest
    # picks the Hotspot zone. nil when the controller has no zones (older
    # than Network 9), in which case --zone is an error and --guest falls
    # back to the legacy guest purpose.
    def choose_zone(zones, wanted, guest:)
      if zones.nil?
        abort 'This controller has no firewall zones (Network 9 or later), so --zone cannot be used.' if wanted
        return nil
      end

      key = wanted || (guest ? FirewallZone::GUEST_KEY : nil)
      return nil if key.nil?

      zone = FirewallZone.find(zones, key)
      return zone if zone

      abort "No firewall zone matches #{key.inspect}. Zones: #{zones.map { |z| z['name'] }.join(', ')}."
    end

    def zone_suffix(zone)
      zone ? " in the #{zone['name']} zone" : ''
    end

    # Everything that would break if the network went away.
    def network_references(client, network_id)
      refs = []
      Array(client.optional(:wlans)).each do |w|
        refs << "WLAN '#{w['name']}' uses it" if w['networkconf_id'] == network_id
      end
      client.known_clients.each do |u|
        next unless u['virtual_network_override_enabled'] && u['virtual_network_override_id'] == network_id

        refs << "client #{client_label(u)} is pinned to it"
      end
      refs
    end

    def network_names_by_id(nets)
      nets.each_with_object({}) { |n, h| h[n['_id']] = n['vlan'] ? "#{n['name']} (VLAN #{n['vlan']})" : n['name'] }
    end

    def client_label(user)
      name = user['name'] || user['hostname']
      name ? "'#{name}' (#{user['mac']})" : user['mac']
    end

    def describe_network_change(attrs, zone)
      attrs.map do |key, value|
        case key
        when 'vlan_enabled'     then nil
        when 'firewall_zone_id' then "zone: #{zone['name']}"
        when 'dhcpd_start'      then "dhcp range: #{value}-#{attrs['dhcpd_stop']}"
        when 'dhcpd_stop'       then nil
        else "#{key}: #{value}"
        end
      end.compact
    end

    # A secret given on the command line, or "-" to read it from a hidden
    # prompt (or stdin when piped) so it stays out of shell history.
    def read_secret(value, prompt:)
      return value unless value == '-'

      secret = ($stdin.tty? ? IO.console.getpass(prompt) : $stdin.gets.to_s).chomp
      abort 'No value provided.' if secret.empty?
      secret
    end
  end
end
