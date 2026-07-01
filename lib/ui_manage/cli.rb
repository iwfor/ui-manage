require 'thor'
require 'io/console'

module UiManage
  class CLI < Thor
    def self.exit_on_failure? = true

    def self.start(args = ARGV, config = {})
      if (args & %w[--help -h]).any?
        cmd = args.find { |a| !a.start_with?('-') }
        return super(['help', cmd], config) if cmd && cmd != 'help'
      end
      super
    end

    def self.handle_argument_error(command, error, args, arity)
      name = [command.ancestor_name, command.name].compact.join(' ')
      abort "ERROR: '#{basename} #{name}' received the wrong number of arguments " \
            "(expected #{arity}, got #{args.length}).\n" \
            "Run '#{basename} #{name} --help' for usage."
    end

    # Groups commands into three tiers, separated by blank lines: control
    # commands (`help`, `login`, `use-device`, `remove-device`), then
    # `report`, then the individual read commands alphabetically.
    def self.sort_commands!(list)
      control = %w[help login use-device remove-device]
      report  = %w[report]

      list.sort_by! do |item|
        name = item[0].to_s.split(/\s+/)[1].to_s
        if (idx = control.index(name))
          [0, idx]
        elsif report.include?(name)
          [1, 0]
        else
          [2, name]
        end
      end

      control_idx = list.rindex { |item| control.include?(item[0].to_s.split(/\s+/)[1]) }
      list.insert(control_idx + 1, ['', '']) if control_idx

      report_idx = list.index { |item| report.include?(item[0].to_s.split(/\s+/)[1]) }
      list.insert(report_idx + 1, ['', '']) if report_idx
    end

    remove_command :tree, undefine: true

    class_option :verbose, aliases: '-v', type: :boolean, default: false,
                            desc: 'Print the curl commands being executed (API keys, tokens, and request bodies are redacted)'

    # -------------------------------------------------------------------------
    # Device management
    # -------------------------------------------------------------------------

    desc 'login HOST', 'Add and authenticate a UniFi device'
    long_desc <<~DESC
      Connects to a UniFi controller and saves its credentials for future commands.

      HOST is the IP address or hostname of the machine running the UniFi Network
      application — typically your UDM Pro (e.g. 192.168.1.1) or a self-hosted
      controller. This is a network address, not a UniFi concept.

      --site is a separate concept: a single controller can manage multiple logical
      sites (e.g. "home", "office"). The site name is the internal identifier shown
      in UniFi Network under Settings > Site. Most single-location setups never
      change it from the factory value, which is literally the string "default".

      --api-key switches to API key authentication instead of username/password.
      API keys are supported on UniFi Network Application 8.x and later and can be
      generated under Settings → Control Plane → API. Pass the key as the option
      value — username and password are not used. The key is stored encrypted using
      the same secret.key as passwords.

        ui-manage login --api-key $(pass show udm-pro/api-key) 192.168.1.1

      To avoid the key appearing in shell history, assign it first:

        read -rs API_KEY && ui-manage login --api-key "$API_KEY" 192.168.1.1
    DESC
    option :name,    aliases: '-n', type: :string,  desc: 'Alias for this device (default: hostname/IP)'
    option :site,    aliases: '-s', type: :string,  desc: 'UniFi site name — the internal identifier shown in Network > Settings > Site (most installs use "default")', default: 'default'
    option :username, aliases: '-u', type: :string,  desc: 'Username for local account auth (will prompt if omitted and --api-key not set)'
    option :api_key, aliases: '-k', type: :string,  desc: 'API key for authentication (Network App 8.x+). Pass the key directly or use $(pass show ...) / $(op read ...)'
    def login(host)
      name   = options[:name] || host
      config = Config.new

      if options[:api_key]
        api_key = options[:api_key]
        say "Connecting to #{host} with API key..."

        client = Client.new(host: host, site: options[:site], api_key: api_key, verbose: options[:verbose])
        client.sysinfo # verify key works

        config.add_device(
          name:              name,
          host:              host,
          site:              options[:site],
          encrypted_api_key: Encryption.encrypt(api_key)
        )
      else
        username = options[:username] || ask('Username: ')
        password = IO.console.getpass('Password: ')
        say "Connecting to #{host} as #{username}..."

        client = Client.new(host: host, site: options[:site], username: username, password: password, verbose: options[:verbose])
        client.login

        config.add_device(
          name:               name,
          host:               host,
          site:               options[:site],
          username:           username,
          encrypted_password: Encryption.encrypt(password)
        )
      end

      say "Device '#{name}' (#{host}) saved successfully."
      say 'Set as default device.' if config.devices.length == 1
    rescue Client::AuthError => e
      abort "Authentication error: #{e.message}"
    rescue Client::ApiError => e
      abort "Connection error: #{e.message}"
    end

    desc 'devices', 'List configured devices'
    def devices
      config  = Config.new
      devs    = config.devices
      default = config.default_device_name

      if devs.empty?
        say 'No devices configured. Run `ui-manage login HOST` to add one.'
        return
      end

      rows = devs.map do |d|
        marker  = d['name'] == default ? '*' : ' '
        auth    = d['encrypted_api_key'] ? 'api-key' : "password (#{d['username']})"
        [marker, d['name'], d['host'], d['site'], auth]
      end

      Formatter.table(
        ['', 'Name', 'Host', 'Site', 'Auth'],
        rows,
        title: 'Configured Devices (* = default)'
      )
    end

    desc 'use-device NAME', 'Set the default device'
    map 'use-device' => :use_device
    def use_device(name)
      Config.new.set_default(name)
      say "Default device set to '#{name}'."
    rescue => e
      abort e.message
    end

    desc 'remove-device NAME', 'Remove a configured device'
    map 'remove-device' => :remove_device
    def remove_device(name)
      Config.new.remove_device(name)
      say "Device '#{name}' removed."
    end

    # -------------------------------------------------------------------------
    # Firewall
    # -------------------------------------------------------------------------

    desc 'firewall', 'Show firewall rules'
    option :device,   aliases: '-d', type: :string,  desc: 'Device name (uses default if omitted)'
    option :json,     aliases: '-j', type: :boolean, desc: 'Output raw JSON', default: false
    option :ruleset,  aliases: '-r', type: :string,  desc: 'Filter by ruleset (WAN_IN, WAN_OUT, LAN_IN, etc.)'
    option :enabled,  aliases: '-e', type: :boolean, desc: 'Show only enabled rules'
    def firewall
      show_firewall
    end

    # -------------------------------------------------------------------------
    # Port forwards
    # -------------------------------------------------------------------------

    desc 'port-forwards', 'Show port forwarding rules'
    map 'port-forwards' => :port_forwards
    option :device,  aliases: '-d', type: :string,  desc: 'Device name'
    option :json,    aliases: '-j', type: :boolean, desc: 'Output raw JSON', default: false
    option :enabled, aliases: '-e', type: :boolean, desc: 'Show only enabled rules'
    def port_forwards
      show_port_forwards
    end

    # -------------------------------------------------------------------------
    # DHCP / Networks
    # -------------------------------------------------------------------------

    desc 'dhcp', 'Show DHCP network configuration, leases, and reservations'
    option :device,  aliases: '-d', type: :string,  desc: 'Device name'
    option :json,    aliases: '-j', type: :boolean, desc: 'Output raw JSON', default: false
    option :all,     aliases: '-a', type: :boolean, desc: 'Show all networks (not just DHCP)', default: false
    option :leases,  aliases: '-l', type: :boolean, desc: 'Show DHCP leases and static reservations instead of network config', default: false
    def dhcp
      show_dhcp
    end

    # -------------------------------------------------------------------------
    # Port power (PoE)
    # -------------------------------------------------------------------------

    desc 'port-power', 'Show PoE port power status'
    map 'port-power' => :port_power
    option :device, aliases: '-d', type: :string,  desc: 'Device name'
    option :json,   aliases: '-j', type: :boolean, desc: 'Output raw JSON', default: false
    option :active, aliases: '-a', type: :boolean, desc: 'Show only active PoE ports', default: false
    def port_power
      show_port_power
    end

    # -------------------------------------------------------------------------
    # Ports
    # -------------------------------------------------------------------------

    desc 'ports', 'Show what is connected to each switch/gateway port'
    option :device, aliases: '-d', type: :string,  desc: 'Device name'
    option :json,   aliases: '-j', type: :boolean, desc: 'Output raw JSON', default: false
    option :up,     aliases: '-u', type: :boolean, desc: 'Show only ports that are up', default: false
    option :anon,   aliases: ['--anonymous'], type: :boolean, default: false,
                    desc: 'Replace MAC addresses and IP addresses with friendly placeholders'
    def ports
      show_ports(anon: Anonymizer.new(options[:anon]))
    end

    # -------------------------------------------------------------------------
    # Storage
    # -------------------------------------------------------------------------

    desc 'storage', 'Show storage information'
    option :device, aliases: '-d', type: :string,  desc: 'Device name'
    option :json,   aliases: '-j', type: :boolean, desc: 'Output raw JSON', default: false
    def storage
      show_storage
    end

    # -------------------------------------------------------------------------
    # Memory
    # -------------------------------------------------------------------------

    desc 'memory', 'Show memory usage'
    option :device, aliases: '-d', type: :string,  desc: 'Device name'
    option :json,   aliases: '-j', type: :boolean, desc: 'Output raw JSON', default: false
    def memory
      show_memory
    end

    # -------------------------------------------------------------------------
    # CPU
    # -------------------------------------------------------------------------

    desc 'cpu', 'Show CPU usage and load'
    option :device, aliases: '-d', type: :string,  desc: 'Device name'
    option :json,   aliases: '-j', type: :boolean, desc: 'Output raw JSON', default: false
    def cpu
      show_cpu
    end

    # -------------------------------------------------------------------------
    # Identity
    # -------------------------------------------------------------------------

    desc 'identity', 'Show device identity (name, serial, MAC, firmware, and other identifiers)'
    long_desc <<~DESC
      Shows identifying information for the gateway/default device: name, model,
      serial number, MAC address, firmware version, IP address, and internal
      device ID.

      --anon (or --anonymous) replaces the serial number, MAC address, device ID,
      and IP address with realistic-looking placeholder values, so the output can
      be shared (screenshots, support tickets, bug reports) without exposing real
      identifiers. Placeholders use formats reserved for documentation/examples —
      IPs come from the 192.0.2.0/24, 198.51.100.0/24, and 203.0.113.0/24 ranges
      (RFC 5737) and MACs use the locally-administered 02:00:00 prefix — so they
      read as unambiguous placeholders rather than real values.
    DESC
    option :device, aliases: '-d', type: :string,  desc: 'Device name'
    option :json,   aliases: '-j', type: :boolean, desc: 'Output raw JSON', default: false
    option :anon,   aliases: ['--anonymous'], type: :boolean, default: false,
                    desc: 'Replace serial number, MAC address, device ID, and IP address with friendly placeholders'
    def identity
      show_identity(anon: Anonymizer.new(options[:anon]))
    end

    # -------------------------------------------------------------------------
    # Gateway (WAN)
    # -------------------------------------------------------------------------

    desc 'gateway', 'Show internet gateway (WAN) information'
    long_desc <<~DESC
      Shows the device's internet uplink(s) — typically reported as wan1 (and
      wan2 on dual-WAN setups): connection status, type (DHCP/static/PPPoE),
      public IP, ISP gateway IP, netmask, DNS servers, and the WAN interface's
      MAC address.

      --anon (or --anonymous) replaces the public IP, gateway IP, DNS server
      IPs, and WAN MAC address with friendly placeholders.
    DESC
    option :device, aliases: '-d', type: :string,  desc: 'Device name'
    option :json,   aliases: '-j', type: :boolean, desc: 'Output raw JSON', default: false
    option :anon,   aliases: ['--anonymous'], type: :boolean, default: false,
                    desc: 'Replace IP addresses and MAC address with friendly placeholders'
    def gateway
      show_gateway(anon: Anonymizer.new(options[:anon]))
    end

    # -------------------------------------------------------------------------
    # Clients
    # -------------------------------------------------------------------------

    desc 'clients', 'Show every client connected to the network'
    long_desc <<~DESC
      Lists every wired and wireless client the controller currently knows
      about: name, IP, MAC, connection type, what switch port or access point
      (and SSID) it's connected through, wireless signal, and last-seen time.

      Sorted by name by default; use --ip to sort by IP address instead.
      Clients with no IP address are listed last.

      --anon (or --anonymous) replaces IP and MAC addresses with friendly
      placeholders.
    DESC
    option :device, aliases: '-d', type: :string,  desc: 'Device name'
    option :json,   aliases: '-j', type: :boolean, desc: 'Output raw JSON', default: false
    option :ip,     aliases: '-i', type: :boolean, default: false, desc: 'Sort by IP address instead of name'
    option :anon,   aliases: ['--anonymous'], type: :boolean, default: false,
                    desc: 'Replace MAC addresses and IP addresses with friendly placeholders'
    def clients
      show_clients(anon: Anonymizer.new(options[:anon]))
    end

    # -------------------------------------------------------------------------
    # Report
    # -------------------------------------------------------------------------

    desc 'report', 'Generate a full report combining all information commands'
    long_desc <<~DESC
      Runs every information command (identity, cpu, memory, storage, gateway,
      clients, firewall, port-forwards, dhcp, port-power, ports) against a
      single device and prints them together as one report.

      --anon (or --anonymous) replaces MAC addresses and IP addresses throughout
      the report with realistic-looking placeholders (and, in the identity
      section, the serial number and device ID too) — useful for sharing the
      report without exposing real network details. The same real value always
      maps to the same placeholder within one report run, so entries stay
      cross-referenceable across sections.
    DESC
    option :device, aliases: '-d', type: :string,  desc: 'Device name'
    option :anon,   aliases: ['--anonymous'], type: :boolean, default: false,
                    desc: 'Replace MAC addresses, IP addresses, serial number, and device ID with friendly placeholders'
    def report
      anon   = Anonymizer.new(options[:anon])
      client = resolve_client

      report_header('Identity')
      show_identity(client: client, anon: anon)

      report_header('CPU')
      show_cpu(client: client, anon: anon)

      report_header('Memory')
      show_memory(client: client, anon: anon)

      report_header('Storage')
      show_storage(client: client, anon: anon)

      report_header('Gateway (WAN)')
      show_gateway(client: client, anon: anon)

      report_header('Clients')
      show_clients(client: client, anon: anon)

      report_header('Firewall Rules')
      show_firewall(client: client, anon: anon)

      report_header('Port Forwards')
      show_port_forwards(client: client, anon: anon)

      report_header('DHCP Networks')
      show_dhcp(client: client, anon: anon)

      report_header('DHCP Leases & Reservations')
      show_dhcp_leases(client: client, anon: anon)

      report_header('Port Power (PoE)')
      show_port_power(client: client, anon: anon)

      report_header('Ports')
      show_ports(client: client, anon: anon)
    end

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    private

    def resolve_client
      config = Config.new

      dev = begin
        config.device(options[:device])
      rescue => e
        abort e.message
      end

      abort 'No devices configured. Run `ui-manage login HOST` to add one.' if dev.nil?

      if dev['encrypted_api_key']
        Client.new(
          host:       dev['host'],
          site:       dev['site'] || 'default',
          verify_ssl: false,
          api_key:    Encryption.decrypt(dev['encrypted_api_key']),
          verbose:    options[:verbose]
        )
      else
        Client.new(
          host:       dev['host'],
          site:       dev['site'] || 'default',
          verify_ssl: false,
          username:   dev['username'],
          password:   Encryption.decrypt(dev['encrypted_password']),
          verbose:    options[:verbose]
        )
      end
    end

    def with_client(client = nil)
      client ||= resolve_client
      yield client
    rescue Client::AuthError => e
      abort "Authentication error: #{e.message}"
    rescue Client::ApiError => e
      abort "API error: #{e.message}"
    end

    def report_header(label)
      puts
      puts '=' * 70
      puts label
      puts '=' * 70
    end

    def show_firewall(client: nil, anon: Anonymizer.new(false))
      rules = with_client(client) { |c| c.firewall_rules }
      rules = rules.select { |r| r['ruleset'] == options[:ruleset].upcase } if options[:ruleset]
      rules = rules.select { |r| r['enabled'] } if options[:enabled]

      return Formatter.json(anon.deep_scrub(rules)) if options[:json]

      if rules.empty?
        say 'No firewall rules found.'
        return
      end

      rows = rules.map do |r|
        src  = format_address(r['src_address'], r['src_firewallgroup_ids'], anon)
        dst  = format_address(r['dst_address'], r['dst_firewallgroup_ids'], anon)
        [
          r['name'],
          Formatter.enabled_badge(r['enabled']),
          r['ruleset'],
          r['rule_index'] || r['index'],
          r['action'],
          r['protocol'] || 'all',
          src,
          dst
        ]
      end

      Formatter.table(
        %w[Name Enabled Ruleset Index Action Protocol Source Destination],
        rows,
        title: 'Firewall Rules'
      )
    end

    def show_port_forwards(client: nil, anon: Anonymizer.new(false))
      rules = with_client(client) { |c| c.port_forwards }
      rules = rules.select { |r| r['enabled'] } if options[:enabled]

      return Formatter.json(anon.deep_scrub(rules)) if options[:json]

      if rules.empty?
        say 'No port forwarding rules found.'
        return
      end

      rows = rules.map do |r|
        [
          r['name'],
          Formatter.enabled_badge(r['enabled']),
          r['proto'] || 'tcp/udp',
          anon.scrub(r['src']),
          r['dst_port'],
          anon.scrub(r['fwd']),
          r['fwd_port'],
          r['log'] ? 'yes' : 'no'
        ]
      end

      Formatter.table(
        %w[Name Enabled Protocol Source Ext.Port Forward.IP Int.Port Log],
        rows,
        title: 'Port Forwarding Rules'
      )
    end

    def show_dhcp(client: nil, anon: Anonymizer.new(false))
      return show_dhcp_leases(client: client, anon: anon) if options[:leases]

      nets = with_client(client) { |c| c.networks }
      nets = nets.select { |n| n['dhcpd_enabled'] } unless options[:all]

      return Formatter.json(anon.deep_scrub(nets)) if options[:json]

      if nets.empty?
        say 'No DHCP-enabled networks found. Use --all to show all networks.'
        return
      end

      rows = nets.map do |n|
        [
          n['name'],
          anon.scrub(n['ip_subnet'] || n['subnet']),
          anon.scrub(n['dhcpd_start']),
          anon.scrub(n['dhcpd_stop']),
          n['dhcpd_leasetime'] ? "#{n['dhcpd_leasetime']}s" : 'N/A',
          n.dig('dhcpd_dns') ? Array(n['dhcpd_dns']).map { |d| anon.scrub(d) }.join(', ') : 'default',
          n['vlan'] || n['vlan_enabled'] ? (n['vlan'] || 'yes') : 'no',
          n['purpose'] || 'corporate'
        ]
      end

      Formatter.table(
        ['Network', 'Subnet', 'DHCP Start', 'DHCP Stop', 'Lease', 'DNS', 'VLAN', 'Purpose'],
        rows,
        title: options[:all] ? 'Networks' : 'DHCP Networks'
      )
    end

    def show_dhcp_leases(client: nil, anon: Anonymizer.new(false))
      clients = with_client(client) { |c| c.dhcp_leases }

      return Formatter.json(anon.deep_scrub(clients)) if options[:json]

      reservations = clients.select { |c| c['use_fixedip'] }
      leases       = clients.select { |c| !c['use_fixedip'] && c['ip'] }

      if reservations.any?
        rows = reservations.map do |c|
          [
            c['name'] || c['hostname'] || '—',
            anon.mac(c['mac']),
            anon.ip(c['fixed_ip']),
            c['oui'] || '—',
            format_last_seen(c['last_seen'])
          ]
        end
        Formatter.table(
          ['Name', 'MAC', 'Reserved IP', 'Vendor', 'Last Seen'],
          rows,
          title: 'Static Reservations'
        )
      end

      if leases.any?
        rows = leases.sort_by { |c| ip_sort_key(c['ip']) }.map do |c|
          [
            c['name'] || c['hostname'] || '—',
            anon.mac(c['mac']),
            anon.ip(c['ip']),
            c['oui'] || '—',
            format_last_seen(c['last_seen'])
          ]
        end
        Formatter.table(
          ['Name', 'MAC', 'IP', 'Vendor', 'Last Seen'],
          rows,
          title: 'Dynamic Leases'
        )
      end

      say 'No leases or reservations found.' if reservations.empty? && leases.empty?
    end

    def show_port_power(client: nil, anon: Anonymizer.new(false))
      devs = with_client(client) { |c| c.devices }

      return Formatter.json(anon.deep_scrub(devs)) if options[:json]

      rows = []
      devs.each do |dev|
        dev_name = dev['name'] || dev['model'] || anon.mac(dev['mac'])
        ports = dev['port_table'] || []
        ports.each do |port|
          next unless port['poe_caps'] && port['poe_caps'].to_i > 0
          next if options[:active] && port['poe_power'].to_f == 0

          rows << [
            dev_name,
            port['port_idx'] || port['name'],
            port['name'],
            port['poe_mode'] || 'off',
            port['poe_good'] ? 'OK' : (port['poe_mode'] == 'off' ? '-' : 'FAULT'),
            port['poe_power']  ? "#{port['poe_power']}W"   : '-',
            port['poe_voltage'] ? "#{port['poe_voltage']}V" : '-',
            port['poe_current'] ? "#{port['poe_current']}A" : '-'
          ]
        end
      end

      if rows.empty?
        say 'No PoE ports found.'
        return
      end

      Formatter.table(
        %w[Device Port Name Mode Status Power Voltage Current],
        rows,
        title: 'PoE Port Power'
      )
    end

    def show_ports(client: nil, anon: Anonymizer.new(false))
      devs, clients = with_client(client) { |c| [c.devices, c.clients] }

      return Formatter.json(anon.deep_scrub(devs)) if options[:json]

      rows = []
      devs.each do |dev|
        dev_name   = dev['name'] || dev['model'] || anon.mac(dev['mac'])
        port_table = dev['port_table'] || []

        port_table.each do |port|
          next if options[:up] && !port['up']

          connected = clients.select do |cl|
            cl['sw_mac'] == dev['mac'] && cl['sw_port'] == port['port_idx']
          end
          connected_names = connected.map { |cl| cl['name'] || cl['hostname'] || anon.mac(cl['mac']) }

          # The switch's own MAC table (mac_table_count) is often more complete
          # than the controller's per-client port resolution — e.g. devices behind
          # an unmanaged switch are frequently seen at the hardware level but never
          # get assigned a sw_port in /stat/sta, so they're invisible to the
          # client-correlation above. Surface the gap instead of hiding it.
          unresolved = port['mac_table_count'].to_i - connected_names.size

          connected_label =
            if connected_names.any?
              lines = connected_names.dup
              lines << "+ #{unresolved} more (unresolved by controller)" if unresolved > 0
              # One device per line so multi-device ports (e.g. behind a dumb
              # switch) don't get lost in an overflowing comma-joined cell.
              lines.join("\n")
            elsif port['is_uplink']
              'Uplink'
            elsif unresolved > 0
              "#{unresolved} device(s) (unresolved by controller)"
            elsif port['up']
              'Unknown device'
            else
              '-'
            end

          rows << [
            dev_name,
            port['port_idx'],
            port['name'],
            port['up'] ? 'up' : 'down',
            format_speed(port['speed']),
            port_poe_label(port),
            connected_label
          ]
        end
      end

      if rows.empty?
        say 'No ports found.'
        return
      end

      Formatter.table(
        %w[Device Port Name Status Speed PoE Connected],
        rows,
        title: 'Ports'
      )
    end

    def show_storage(client: nil, anon: Anonymizer.new(false))
      gw = with_client(client) { |c| c.gateway_device }

      return Formatter.json(anon.deep_scrub(gw&.dig('storage') || gw)) if options[:json]

      storage = gw&.dig('storage')

      if storage.nil? || storage.empty?
        say 'Storage information not available from this device.'
        say 'This endpoint requires UDM Pro with firmware 1.9+.'
        return
      end

      rows = storage.map do |disk|
        used  = disk['used'].to_i
        size  = disk['size'].to_i
        avail = size - used
        [
          disk['name'] || disk['mount_point'],
          disk['type'] || 'unknown',
          Formatter.bytes_human(size),
          Formatter.bytes_human(used),
          Formatter.bytes_human(avail),
          Formatter.percent(used, size),
          disk['mount_point'] || '-'
        ]
      end

      Formatter.table(
        %w[Name Type Size Used Available Use% Mount],
        rows,
        title: 'Storage'
      )
    end

    def show_memory(client: nil, anon: Anonymizer.new(false))
      gw = with_client(client) { |c| c.gateway_device }

      return Formatter.json(anon.deep_scrub(gw)) if options[:json]

      stats = gw&.dig('sys_stats') || {}
      name  = gw&.dig('name') || gw&.dig('model') || 'Gateway'

      total  = stats['mem_total'].to_i
      used   = stats['mem_used'].to_i
      buffer = stats['mem_buffer'].to_i
      free   = total - used

      if total == 0
        say "Memory information not available for #{name}."
        return
      end

      Formatter.section("Memory — #{name}")
      Formatter.kv([
        ['Total',    Formatter.bytes_human(total)],
        ['Used',     Formatter.bytes_human(used)],
        ['Buffers',  Formatter.bytes_human(buffer)],
        ['Free',     Formatter.bytes_human(free)],
        ['Usage',    Formatter.percent(used, total)]
      ])

      # Per-subsystem breakdown if available
      subsystems = gw['system-stats']
      return unless subsystems&.key?('mem')

      Formatter.section('Controller Reported')
      Formatter.kv([['Memory', "#{subsystems['mem']}%"]])
    end

    def show_cpu(client: nil, anon: Anonymizer.new(false))
      gw = with_client(client) { |c| c.gateway_device }

      return Formatter.json(anon.deep_scrub(gw)) if options[:json]

      stats = gw&.dig('sys_stats') || {}
      name  = gw&.dig('name') || gw&.dig('model') || 'Gateway'

      l1  = stats['loadavg_1']
      l5  = stats['loadavg_5']
      l15 = stats['loadavg_15']

      if l1.nil? && l5.nil? && l15.nil?
        say "CPU information not available for #{name}."
        return
      end

      Formatter.section("CPU — #{name}")
      pairs = [
        ['Load (1m)',   l1  || 'N/A'],
        ['Load (5m)',   l5  || 'N/A'],
        ['Load (15m)',  l15 || 'N/A']
      ]

      # Some firmwares report CPU % directly
      if (sys = gw['system-stats']) && sys['cpu']
        pairs << ['CPU Usage', "#{sys['cpu']}%"]
      end

      if (temps = gw['temperatures']) && temps.any?
        temps.each { |t| pairs << ["Temp (#{t['name']})", "#{t['value']}°C"] }
      end

      Formatter.kv(pairs)
    end

    def show_identity(client: nil, anon: Anonymizer.new(false))
      gw = with_client(client) { |c| c.gateway_device }

      if options[:json]
        data = anon.deep_scrub(gw)
        if anon.enabled? && data
          data['serial']    = anon.serial(gw['serial'])    if data.key?('serial')
          data['_id']       = anon.device_id(gw['_id'])     if data.key?('_id')
          data['device_id'] = anon.device_id(gw['device_id']) if data.key?('device_id')
        end
        return Formatter.json(data)
      end

      if gw.nil?
        say 'No gateway device found.'
        return
      end

      name = gw['name'] || gw['model'] || 'Gateway'

      Formatter.section("Identity — #{name}")
      Formatter.kv([
        ['Name',          gw['name'] || 'N/A'],
        ['Model',         gw['model'] || 'N/A'],
        ['Type',          gw['type'] || 'N/A'],
        ['Serial',        anon.serial(gw['serial']) || 'N/A'],
        ['MAC Address',   anon.mac(gw['mac']) || 'N/A'],
        ['Firmware',      gw['version'] || 'N/A'],
        ['IP Address',    anon.ip(gw['ip']) || 'N/A'],
        ['Device ID',     anon.device_id(gw['_id'] || gw['device_id']) || 'N/A'],
        ['Adopted',       gw.key?('adopted') ? Formatter.enabled_badge(gw['adopted']) : 'N/A'],
        ['Uptime',        gw['uptime'] ? format_uptime(gw['uptime']) : 'N/A']
      ])
    end

    def show_gateway(client: nil, anon: Anonymizer.new(false))
      gw = with_client(client) { |c| c.gateway_device }

      return Formatter.json(anon.deep_scrub(gw)) if options[:json]

      if gw.nil?
        say 'No gateway device found.'
        return
      end

      wans = [['WAN1', gw['wan1']], ['WAN2', gw['wan2']]].select { |_, wan| wan && !wan.empty? }

      if wans.empty?
        say "No WAN/internet information available for #{gw['name'] || gw['model'] || 'Gateway'}."
        return
      end

      wans.each do |label, wan|
        wan_label = wan['name'] || label
        dns       = wan['dns'] ? Array(wan['dns']).map { |d| anon.ip(d) }.join(', ') : 'N/A'

        Formatter.section("Gateway — #{wan_label}")
        Formatter.kv([
          ['Status',      wan['up'] ? 'up' : 'down'],
          ['Enabled',     wan.key?('enable') ? Formatter.enabled_badge(wan['enable']) : 'N/A'],
          ['Type',        wan['type'] || 'N/A'],
          ['Public IP',   anon.ip(wan['ip']) || 'N/A'],
          ['Gateway IP',  anon.ip(wan['gateway'] || wan['gw']) || 'N/A'],
          ['Netmask',     wan['netmask'] || 'N/A'],
          ['DNS',         dns],
          ['MAC Address', anon.mac(wan['mac']) || 'N/A'],
          ['Interface',   wan['ifname'] || 'N/A'],
          ['Speed',       format_speed(wan['speed'], 'N/A')],
          ['Max Speed',   format_speed(wan['max_speed'], 'N/A')]
        ])
      end
    end

    def show_clients(client: nil, anon: Anonymizer.new(false))
      devs, sta = with_client(client) { |c| [c.devices, c.clients] }

      return Formatter.json(anon.deep_scrub(sta)) if options[:json]

      if sta.empty?
        say 'No clients found.'
        return
      end

      dev_by_mac = devs.each_with_object({}) { |d, h| h[d['mac']] = d['name'] || d['model'] }

      sorted = if options[:ip]
        sta.sort_by { |c| ip_sort_key(c['ip']) }
      else
        sta.sort_by { |c| (c['name'] || c['hostname'] || '').downcase }
      end

      rows = sorted.map do |c|
        wired = c['is_wired']
        via =
          if wired
            sw = dev_by_mac[c['sw_mac']] || anon.mac(c['sw_mac']) || '—'
            c['sw_port'] ? "#{sw} port #{c['sw_port']}" : sw
          else
            ap = dev_by_mac[c['ap_mac']] || anon.mac(c['ap_mac']) || '—'
            c['essid'] ? "#{ap} (#{c['essid']})" : ap
          end

        [
          c['name'] || c['hostname'] || '—',
          anon.ip(c['ip']) || '—',
          anon.mac(c['mac']),
          wired ? 'wired' : 'wireless',
          via,
          wired ? '-' : (c['signal'] ? "#{c['signal']} dBm" : '-'),
          format_last_seen(c['last_seen'])
        ]
      end

      Formatter.table(
        ['Name', 'IP', 'MAC', 'Type', 'Connected Via', 'Signal', 'Last Seen'],
        rows,
        title: "Clients (#{rows.size})"
      )
    end

    # Sorts dotted-quad IPs numerically per octet; missing/invalid IPs sort last.
    def ip_sort_key(ip)
      return [256, 256, 256, 256] if ip.nil? || ip.to_s.empty?

      ip.to_s.split('.').map(&:to_i)
    rescue
      [256, 256, 256, 256]
    end

    def format_last_seen(ts)
      return '—' unless ts
      t = Time.at(ts.to_i)
      ago = (Time.now - t).to_i
      case ago
      when 0..59      then "#{ago}s ago"
      when 60..3599   then "#{ago / 60}m ago"
      when 3600..86399 then "#{ago / 3600}h ago"
      else t.strftime('%Y-%m-%d')
      end
    end

    # Formats a speed given in Mbps, switching to Gbps at 1000+ (e.g. 2500 ->
    # "2.5 Gbps", 1000 -> "1 Gbps", 100 -> "100 Mbps").
    def format_speed(mbps, none = '-')
      n = mbps.to_i
      return none if n <= 0
      return "#{n} Mbps" if n < 1000

      gbps = n / 1000.0
      gbps_str = gbps == gbps.to_i ? gbps.to_i.to_s : format('%.1f', gbps)
      "#{gbps_str} Gbps"
    end

    def port_poe_label(port)
      return '-' unless port['poe_caps'].to_i > 0 || port['port_poe']
      return 'off' unless port['poe_enable']

      port['poe_power'].to_f > 0 ? "#{port['poe_power']}W" : 'on'
    end

    def format_uptime(seconds)
      seconds = seconds.to_i
      days, rem = seconds.divmod(86400)
      hours, rem = rem.divmod(3600)
      minutes, _ = rem.divmod(60)

      parts = []
      parts << "#{days}d" if days > 0
      parts << "#{hours}h" if hours > 0 || days > 0
      parts << "#{minutes}m"
      parts.join(' ')
    end

    def format_address(addr, group_ids, anon = Anonymizer.new(false))
      parts = []
      parts << anon.scrub(addr) unless addr.nil? || addr.empty?
      parts << "group(#{Array(group_ids).join(',')})" if group_ids&.any?
      parts.empty? ? 'any' : parts.join(', ')
    end
  end
end
