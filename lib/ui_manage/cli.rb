require 'thor'
require 'io/console'

module UiManage
  class CLI < Thor
    include AuditViews

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

    # Declares the option trio shared by the information commands: --device,
    # --json, and — when a description is given — --anon/--anonymous.
    def self.output_options(json: true, anon: nil)
      option :device, aliases: '-d', type: :string,  desc: 'Device name (uses default if omitted)'
      option :json,   aliases: '-j', type: :boolean, desc: 'Output raw JSON', default: false if json
      option :anon,   aliases: ['--anonymous'], type: :boolean, default: false, desc: anon if anon
    end

    # Declares the options shared by commands reading a time-bounded endpoint.
    def self.window_options(default: 24, limit: nil)
      option :within, aliases: '-w', type: :numeric, default: default,
                      desc: 'How many hours back to look'
      option :limit,  aliases: '-l', type: :numeric, default: limit,
                      desc: 'Maximum number of records to request' if limit
    end

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

      Pass "-" as the key to read it from a hidden prompt (or from stdin when
      piped), keeping it out of shell history and the process list:

        ui-manage login --api-key - 192.168.1.1

        pass show udm-pro/api-key | ui-manage login --api-key - 192.168.1.1

      --verify-ssl turns on TLS certificate verification for this device (off by
      default, since UniFi controllers ship with self-signed certificates). Use it
      when your controller has a certificate your system trusts — without it,
      connections are vulnerable to man-in-the-middle interception. The setting is
      saved with the device and applies to every later command.

      --remote-access / --no-remote-access records whether this network is
      supposed to be reachable through UniFi remote (cloud) access. The audit
      compares the controller against this answer, so it is a policy decision
      the tool cannot infer. When neither flag is given and the terminal is
      interactive, login asks; otherwise the setting is left unset and can be
      filled in later with `ui-manage policy`.
    DESC
    option :name,    aliases: '-n', type: :string,  desc: 'Alias for this device (default: hostname/IP)'
    option :site,    aliases: '-s', type: :string,  desc: 'UniFi site name — the internal identifier shown in Network > Settings > Site (most installs use "default")', default: 'default'
    option :username, aliases: '-u', type: :string,  desc: 'Username for local account auth (will prompt if omitted and --api-key not set)'
    option :api_key, aliases: '-k', type: :string,  desc: 'API key for authentication (Network App 8.x+). Pass the key, or "-" to read it from a hidden prompt/stdin'
    option :verify_ssl, type: :boolean, default: false, desc: 'Verify the controller TLS certificate (off by default — UniFi ships self-signed certs). Saved with the device'
    option :remote_access, type: :boolean, desc: 'Whether UniFi remote (cloud) access is expected on this network — recorded for the audit. Prompts when omitted on an interactive terminal'
    def login(host)
      name        = options[:name] || host
      config      = Config.new
      client_args = { host: host, site: options[:site],
                      verify_ssl: options[:verify_ssl], verbose: options[:verbose] }

      creds =
        if options[:api_key]
          api_key = read_api_key(options[:api_key])
          say "Connecting to #{host} with API key..."
          Client.new(**client_args, api_key: api_key).sysinfo # verify key works

          { encrypted_api_key: Encryption.encrypt(api_key) }
        else
          username = options[:username] || ask('Username: ')
          password = IO.console.getpass('Password: ')
          say "Connecting to #{host} as #{username}..."
          Client.new(**client_args, username: username, password: password).login

          { username: username, encrypted_password: Encryption.encrypt(password) }
        end

      config.add_device(name: name, host: host, site: options[:site],
                        verify_ssl: options[:verify_ssl],
                        remote_access_expected: remote_access_policy, **creds)

      say "Device '#{name}' (#{host}) saved successfully."
      say 'Set as default device.' if config.devices.length == 1
    rescue Client::AuthError => e
      abort "Authentication error: #{e.message}"
    rescue Client::ApiError => e
      abort "Connection error: #{e.message}"
    rescue ArgumentError => e
      abort "Error: #{e.message}"
    end

    desc 'devices', 'List configured devices'
    option :sort, aliases: '-s', type: :string, desc: 'Sort by column name (or a unique fragment of one)'
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
        tls     = d['verify_ssl'] ? 'verified' : 'no verify'
        [marker, d['name'], d['host'], d['site'], auth, tls, policy_label(d['remote_access_expected'])]
      end

      Formatter.table(
        ['', 'Name', 'Host', 'Site', 'Auth', 'TLS', 'Remote Access'],
        rows,
        title: 'Configured Devices (* = default)',
        sort:  options[:sort]
      )
    end

    desc 'policy', "Show or set a device's audit policy"
    long_desc <<~DESC
      Audit policy records what this network is *supposed* to look like, so the
      audit can tell a deliberate configuration apart from a finding. It is
      stored per device, alongside that device's connection settings.

      With no options, prints the current policy. Otherwise sets what you pass:

        ui-manage policy --remote-access      # remote access is intended here

        ui-manage policy --no-remote-access   # remote access should be off

        ui-manage policy --unset              # back to "not configured"

      --remote-access covers UniFi remote (cloud) access to the controller.
      Leaving it unset means the audit reports the controller's actual setting
      without judging it.
    DESC
    option :device,        aliases: '-d', type: :string,  desc: 'Device name (uses default if omitted)'
    option :remote_access, type: :boolean, desc: 'Whether UniFi remote (cloud) access is expected on this network'
    option :unset,         type: :boolean, default: false, desc: 'Clear the policy back to "not configured"'
    def policy
      if options[:unset] && !options[:remote_access].nil?
        raise Thor::Error, "ERROR: '--unset' can't be combined with '--remote-access'."
      end

      config = Config.new
      dev    = begin
        config.device(options[:device])
      rescue => e
        abort e.message
      end
      abort 'No devices configured. Run `ui-manage login HOST` to add one.' if dev.nil?

      if options[:unset]
        dev = config.update_device_policy(dev['name'], remote_access_expected: nil)
      elsif !options[:remote_access].nil?
        dev = config.update_device_policy(dev['name'], remote_access_expected: options[:remote_access])
      end

      Formatter.kv(
        [['Remote access expected', policy_label(dev['remote_access_expected'])]],
        title: "Audit policy for '#{dev['name']}'"
      )
    rescue ArgumentError => e
      abort e.message
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

    desc 'completions [SHELL]', 'Print a shell completion script (bash or zsh)'
    long_desc <<~DESC
      Prints a completion script for command and flag names to stdout. Load
      it by adding one of these to your shell startup file:

        echo 'eval "$(ui-manage completions bash)"' >> ~/.bashrc

        echo 'eval "$(ui-manage completions zsh)"' >> ~/.zshrc

      SHELL defaults to the shell named by the $SHELL environment variable
      when omitted.
    DESC
    def completions(shell = nil)
      shell ||= File.basename(ENV['SHELL'].to_s)
      abort 'Could not determine shell from $SHELL — pass bash or zsh explicitly.' if shell.empty?

      commands = self.class.all_commands.reject { |_, c| c.hidden? }.to_h do |name, command|
        flags = (command.options.values + self.class.class_options.values)
                .flat_map { |o| [o.switch_name, *o.aliases] }
        [name.tr('_', '-'), flags]
      end

      puts Completions.generate(shell, prog: File.basename($PROGRAM_NAME), commands: commands)
    rescue ArgumentError => e
      abort e.message
    end

    # -------------------------------------------------------------------------
    # Wireless
    # -------------------------------------------------------------------------

    desc 'wlans', 'Show wireless networks and their security settings'
    long_desc <<~DESC
      Lists every configured SSID with the settings an audit cares about:
      security mode and cipher, protected management frames, WPS, whether it is
      a guest network, whether the SSID is hidden, which band it runs on, and
      which network/VLAN it lands on.

      --insecure-only narrows the list to SSIDs that are open, WEP, WPA1, using
      TKIP, or have WPS enabled — the ones worth acting on first.

      Passphrases are never printed. The Passphrase column reports only whether
      one is set and how long it is, and --anon drops the length too.
    DESC
    output_options anon: 'Replace SSIDs and identifiers with friendly placeholders'
    option :insecure_only, type: :boolean, default: false, desc: 'Only show SSIDs with a weak or broken configuration'
    option :sort, aliases: '-s', type: :string, desc: 'Sort by column name (or a unique fragment of one)'
    def wlans
      show_wlans(anon: Anonymizer.new(options[:anon]))
    end

    desc 'wifi-experience', 'Show per-client wireless signal quality'
    map 'wifi-experience' => :wifi_experience
    long_desc <<~DESC
      Signal, noise, signal-to-noise margin, transmit retry rate, the
      controller's own satisfaction score, and negotiated rates for every
      wireless client. Sorted weakest signal first.

      --signal-below narrows to clients weaker than a given dBm figure (signal
      is negative, so --signal-below -70 shows everything worse than -70 dBm).
    DESC
    output_options anon: 'Replace client names, SSIDs, and identifiers with friendly placeholders'
    option :signal_below, type: :numeric, desc: 'Only show clients whose signal is below this many dBm (e.g. -70)'
    option :sort, aliases: '-s', type: :string, desc: 'Sort by column name (or a unique fragment of one)'
    def wifi_experience
      show_wifi_experience(anon: Anonymizer.new(options[:anon]))
    end

    desc 'rogue-aps', 'Show neighbouring access points this site does not manage'
    map 'rogue-aps' => :rogue_aps
    long_desc <<~DESC
      Access points seen nearby that are not part of this site. The "Ours?"
      column flags any that broadcast one of your own SSIDs — an unmanaged AP
      advertising your network name is the evil-twin case worth investigating.
      It reads "?" when the WLAN list could not be read to compare against.

      --min-signal filters to APs at or above a signal strength, which is a
      rough proxy for proximity (e.g. --min-signal -70).
    DESC
    output_options anon: 'Replace SSIDs, BSSIDs, and identifiers with friendly placeholders'
    window_options
    option :min_signal, type: :numeric, desc: 'Only show APs at or above this signal strength in dBm (e.g. -70)'
    option :sort, aliases: '-s', type: :string, desc: 'Sort by column name (or a unique fragment of one)'
    def rogue_aps
      show_rogue_aps(anon: Anonymizer.new(options[:anon]))
    end

    # -------------------------------------------------------------------------
    # Networks
    # -------------------------------------------------------------------------

    desc 'vlans', 'Show networks and VLANs with their segmentation settings'
    long_desc <<~DESC
      Every configured network: VLAN tag, subnet, purpose, whether DHCP is
      served, whether it is isolated from other networks, and whether it has
      internet access. WAN networks are excluded unless --all is given.
    DESC
    output_options anon: 'Replace subnets and identifiers with friendly placeholders'
    option :all,  aliases: '-a', type: :boolean, default: false, desc: 'Include WAN networks'
    option :sort, aliases: '-s', type: :string, desc: 'Sort by column name (or a unique fragment of one)'
    def vlans
      show_vlans(anon: Anonymizer.new(options[:anon]))
    end

    desc 'vpn', 'Show VPN servers and site-to-site tunnels'
    long_desc <<~DESC
      VPN networks configured on this site — remote-user servers, site-to-site
      tunnels, and VPN client connections — with their type, subnet, and how
      they authenticate.

      The Auth column names the method only. Pre-shared keys, WireGuard private
      keys, and RADIUS secrets are never printed.
    DESC
    output_options anon: 'Replace subnets and identifiers with friendly placeholders'
    option :sort, aliases: '-s', type: :string, desc: 'Sort by column name (or a unique fragment of one)'
    def vpn
      show_vpn(anon: Anonymizer.new(options[:anon]))
    end

    desc 'routes', 'Show static routes and dynamic DNS entries'
    output_options anon: 'Replace networks, hostnames, and identifiers with friendly placeholders'
    option :sort, aliases: '-s', type: :string, desc: 'Sort by column name (or a unique fragment of one)'
    def routes
      show_routes(anon: Anonymizer.new(options[:anon]))
    end

    # -------------------------------------------------------------------------
    # Devices
    # -------------------------------------------------------------------------

    desc 'firmware', 'Show firmware versions and available updates'
    output_options anon: 'Replace device names and identifiers with friendly placeholders'
    option :outdated, aliases: '-o', type: :boolean, default: false, desc: 'Only show devices with an update available'
    option :sort, aliases: '-s', type: :string, desc: 'Sort by column name (or a unique fragment of one)'
    def firmware
      show_firmware(anon: Anonymizer.new(options[:anon]))
    end

    desc 'port-errors', 'Show switch ports reporting errors, drops, or a duplex fault'
    map 'port-errors' => :port_errors
    long_desc <<~DESC
      Per-port receive and transmit error and drop counters across every
      switch and gateway. Only ports with a non-zero counter — or a live link
      that negotiated half duplex — are listed; pass --all for every port.

      Counters are cumulative since the device last booted, so a small number
      on a long-running device is not necessarily a fault. What matters is a
      count that grows between runs.
    DESC
    output_options anon: 'Replace device names and identifiers with friendly placeholders'
    option :all,  aliases: '-a', type: :boolean, default: false, desc: 'Show every port, not just those reporting a fault'
    option :sort, aliases: '-s', type: :string, desc: 'Sort by column name (or a unique fragment of one)'
    def port_errors
      show_port_errors(anon: Anonymizer.new(options[:anon]))
    end

    # -------------------------------------------------------------------------
    # Controller state
    # -------------------------------------------------------------------------

    desc 'health', 'Show controller subsystem health'
    output_options anon: 'Replace IP addresses with friendly placeholders'
    option :sort, aliases: '-s', type: :string, desc: 'Sort by column name (or a unique fragment of one)'
    def health
      show_health(anon: Anonymizer.new(options[:anon]))
    end

    desc 'settings', 'Show site settings'
    long_desc <<~DESC
      The controller's site settings, flattened to one row per setting.

      --section narrows to sections whose key contains the given text (e.g.
      --section mgmt, --section ips, --section guest).

      Passwords, pre-shared keys, and other credentials are replaced with a
      placeholder in both table and JSON output.
    DESC
    output_options anon: 'Replace IP addresses, MAC addresses, and identifiers with friendly placeholders'
    option :section, aliases: '-S', type: :string, desc: 'Only show sections whose key contains this text'
    option :sort, aliases: '-s', type: :string, desc: 'Sort by column name (or a unique fragment of one)'
    def settings
      show_settings(anon: Anonymizer.new(options[:anon]))
    end

    desc 'admins', 'Show site administrators'
    long_desc <<~DESC
      Administrator accounts for this site, with role, super-admin status, and
      whether two-factor authentication is configured.

      The 2FA column reads "unknown" when the controller does not report it —
      an audit must not read a missing field as "no 2FA". API keys usually
      cannot read the admin interface at all, in which case this command says
      so rather than reporting an empty list.
    DESC
    output_options anon: 'Replace administrator names and email addresses with friendly placeholders'
    option :sort, aliases: '-s', type: :string, desc: 'Sort by column name (or a unique fragment of one)'
    def admins
      show_admins(anon: Anonymizer.new(options[:anon]))
    end

    desc 'alarms', 'Show outstanding controller alarms'
    output_options anon: 'Replace IP addresses, MAC addresses, and identifiers with friendly placeholders'
    window_options
    option :archived, type: :boolean, default: false, desc: 'Include alarms that have been archived'
    option :sort, aliases: '-s', type: :string, desc: 'Sort by column name (or a unique fragment of one)'
    def alarms
      show_alarms(anon: Anonymizer.new(options[:anon]))
    end

    desc 'events', 'Show recent controller events'
    long_desc <<~DESC
      Controller events over a time window. --type filters to events whose key
      or message contains the given text (e.g. --type admin, --type disconnect).
    DESC
    output_options anon: 'Replace IP addresses, MAC addresses, and identifiers with friendly placeholders'
    window_options limit: 500
    option :type, aliases: '-t', type: :string, desc: 'Only show events whose key or message contains this text'
    option :sort, aliases: '-s', type: :string, desc: 'Sort by column name (or a unique fragment of one)'
    def events
      show_events(anon: Anonymizer.new(options[:anon]))
    end

    desc 'threats', 'Show IDS/IPS detections'
    long_desc <<~DESC
      Intrusion detection and prevention events, with the signature that fired,
      where the traffic came from and went to, and what the gateway did about
      it.

      --severity filters to detections at or above low, medium, or high.

      This requires Threat Management to be licensed and enabled; without it
      the controller does not serve the endpoint and the command says so.
    DESC
    output_options anon: 'Replace IP addresses and identifiers with friendly placeholders'
    window_options limit: 500
    option :severity, type: :string, desc: 'Only show detections at or above this severity (low, medium, high)'
    option :sort, aliases: '-s', type: :string, desc: 'Sort by column name (or a unique fragment of one)'
    def threats
      show_threats(anon: Anonymizer.new(options[:anon]))
    end

    # -------------------------------------------------------------------------
    # Firewall
    # -------------------------------------------------------------------------

    desc 'firewall', 'Show firewall rules'
    output_options
    option :ruleset, aliases: '-r', type: :string,  desc: 'Filter by ruleset (WAN_IN, WAN_OUT, LAN_IN, etc.)'
    option :enabled, aliases: '-e', type: :boolean, desc: 'Show only enabled rules'
    option :sort,    aliases: '-s', type: :string,  desc: 'Sort by column name (or a unique fragment of one)'
    def firewall
      show_firewall
    end

    # -------------------------------------------------------------------------
    # Port forwards
    # -------------------------------------------------------------------------

    desc 'port-forwards', 'Show port forwarding rules'
    map 'port-forwards' => :port_forwards
    output_options
    option :enabled, aliases: '-e', type: :boolean, desc: 'Show only enabled rules'
    option :sort,    aliases: '-s', type: :string,  desc: 'Sort by column name (or a unique fragment of one)'
    def port_forwards
      show_port_forwards
    end

    # -------------------------------------------------------------------------
    # DHCP / Networks
    # -------------------------------------------------------------------------

    desc 'dhcp', 'Show DHCP network configuration, leases, and reservations'
    output_options
    option :all,    aliases: '-a', type: :boolean, desc: 'Show all networks (not just DHCP)', default: false
    option :leases, aliases: '-l', type: :boolean, desc: 'Show DHCP leases and static reservations instead of network config', default: false
    option :sort,   aliases: '-s', type: :string,  desc: 'Sort by column name (or a unique fragment of one)'
    def dhcp
      show_dhcp
    end

    # -------------------------------------------------------------------------
    # Port power (PoE)
    # -------------------------------------------------------------------------

    desc 'power', 'Show PoE devices/ports and their power state'
    long_desc <<~DESC
      Lists every PoE-capable port across your switches/gateway: current mode,
      status, and power draw.

      Use --on or --off to turn PoE on or off for a specific port instead of
      listing status. Give "DEVICE:PORT", where DEVICE matches a device's full
      name, or a unique substring of one — if the pattern matches more than
      one device, nothing is changed and the ambiguous device names are
      listed so you can be more specific. PORT is the port number shown in
      the Port column.

        ui-manage power --on "Living Room:3"

        ui-manage power --off "Pro Max:12"
    DESC
    output_options
    option :active, aliases: '-a', type: :boolean, desc: 'Show only active PoE ports', default: false
    option :on,     type: :string, desc: 'Turn PoE on for "DEVICE:PORT"'
    option :off,    type: :string, desc: 'Turn PoE off for "DEVICE:PORT"'
    option :sort,   aliases: '-s', type: :string, desc: 'Sort by column name (or a unique fragment of one)'
    def power
      abort 'Use either --on or --off, not both.' if options[:on] && options[:off]

      if options[:on] || options[:off]
        toggle_port_power(options[:on] || options[:off], enabled: !!options[:on])
      else
        show_power
      end
    end

    # -------------------------------------------------------------------------
    # Ports
    # -------------------------------------------------------------------------

    desc 'ports', 'Show what is connected to each switch/gateway port'
    output_options anon: 'Replace MAC addresses and IP addresses with friendly placeholders'
    option :up,   aliases: '-u', type: :boolean, desc: 'Show only ports that are up', default: false
    option :sort, aliases: '-s', type: :string,  desc: 'Sort by column name (or a unique fragment of one)'
    def ports
      show_ports(anon: Anonymizer.new(options[:anon]))
    end

    # -------------------------------------------------------------------------
    # Storage
    # -------------------------------------------------------------------------

    desc 'storage', 'Show storage information'
    output_options
    option :sort, aliases: '-s', type: :string, desc: 'Sort by column name (or a unique fragment of one)'
    def storage
      show_storage
    end

    # -------------------------------------------------------------------------
    # Memory
    # -------------------------------------------------------------------------

    desc 'memory', 'Show memory usage'
    output_options
    def memory
      show_memory
    end

    # -------------------------------------------------------------------------
    # CPU
    # -------------------------------------------------------------------------

    desc 'cpu', 'Show CPU usage and load'
    output_options
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
    output_options anon: 'Replace serial number, MAC address, device ID, and IP address with friendly placeholders'
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
    output_options anon: 'Replace IP addresses and MAC address with friendly placeholders'
    def gateway
      show_gateway(anon: Anonymizer.new(options[:anon]))
    end

    # -------------------------------------------------------------------------
    # Clients
    # -------------------------------------------------------------------------

    desc 'clients [PATTERN]', 'Show every client connected to the network'
    long_desc <<~DESC
      Lists every wired and wireless client the controller currently knows
      about: name, IP, MAC, connection type, what switch port or access point
      (and SSID) it's connected through, wireless signal, and last-seen time.

      PATTERN, if given, filters to clients whose name, hostname, or IP
      contains it (case-insensitive substring match).

      --wired and --wireless further filter to only clients of that
      connection type; they can't be used together.

      Sorted by name by default; use --ip to sort by IP address instead.
      Clients with no IP address are listed last. --sort overrides both,
      sorting by any column name or a unique fragment of one (e.g. --sort
      mac, --sort "last seen").

      --unknown narrows to clients with no name assigned in UniFi — the ones
      that showed up without anyone claiming them. --guest narrows to clients
      on a guest network, --vlan to a single VLAN (use 0 for untagged), and
      --since to clients first seen within the last N hours, which is the
      quickest way to spot something new on the network.

      --anon (or --anonymous) replaces IP and MAC addresses with friendly
      placeholders.
    DESC
    output_options anon: 'Replace MAC addresses and IP addresses with friendly placeholders'
    option :ip,       aliases: '-i', type: :boolean, default: false, desc: 'Sort by IP address instead of name'
    option :wired,    type: :boolean, default: false, desc: 'Only show wired clients'
    option :wireless, type: :boolean, default: false, desc: 'Only show wireless clients'
    option :sort,     aliases: '-s', type: :string, desc: 'Sort by column name (or a unique fragment of one) — overrides --ip'
    option :unknown,  type: :boolean, default: false, desc: 'Only show clients with no name assigned in UniFi'
    option :guest,    type: :boolean, default: false, desc: 'Only show clients on a guest network'
    option :vlan,     type: :numeric, desc: 'Only show clients on this VLAN (0 for untagged)'
    option :since,    type: :numeric, desc: 'Only show clients first seen within this many hours'
    def clients(pattern = nil)
      raise Thor::Error, "ERROR: '--wired' and '--wireless' can't be used together." if options[:wired] && options[:wireless]

      show_clients(anon: Anonymizer.new(options[:anon]), pattern: pattern)
    end

    # -------------------------------------------------------------------------
    # Report
    # -------------------------------------------------------------------------

    desc 'report', 'Generate a full report combining all information commands'
    long_desc <<~DESC
      Runs every information command against a single device and prints them
      together as one report: identity, health, cpu, memory, storage, firmware,
      gateway, clients, wireless experience, wlans, vlans, vpn, firewall,
      port-forwards, routes, dhcp, power, ports, port errors, admins, settings,
      alarms, and threats.

      `events` is left out: it is a raw log rather than a statement of
      configuration, and alarms and threats already carry what is actionable.
      Windowed sections cover the last 24 hours.

      Sections backed by an endpoint this controller or credential cannot
      read say so and the report continues.

      --anon (or --anonymous) replaces MAC addresses and IP addresses throughout
      the report with realistic-looking placeholders (and, in the identity
      section, the serial number and device ID too) — useful for sharing the
      report without exposing real network details. The same real value always
      maps to the same placeholder within one report run, so entries stay
      cross-referenceable across sections.
    DESC
    output_options json: false,
                   anon: 'Replace MAC addresses, IP addresses, serial number, and device ID with friendly placeholders'
    def report
      anon   = Anonymizer.new(options[:anon])
      client = resolve_client

      report_header('Identity')
      show_identity(client: client, anon: anon)

      report_header('Health')
      show_health(client: client, anon: anon)

      report_header('CPU')
      show_cpu(client: client, anon: anon)

      report_header('Memory')
      show_memory(client: client, anon: anon)

      report_header('Storage')
      show_storage(client: client, anon: anon)

      report_header('Firmware')
      show_firmware(client: client, anon: anon)

      report_header('Gateway (WAN)')
      show_gateway(client: client, anon: anon)

      report_header('Clients')
      show_clients(client: client, anon: anon)

      report_header('Wireless Experience')
      show_wifi_experience(client: client, anon: anon)

      report_header('WLANs')
      show_wlans(client: client, anon: anon)

      report_header('Neighbouring Access Points')
      show_rogue_aps(client: client, anon: anon)

      report_header('Networks / VLANs')
      show_vlans(client: client, anon: anon)

      report_header('VPN')
      show_vpn(client: client, anon: anon)

      report_header('Firewall Rules')
      show_firewall(client: client, anon: anon)

      report_header('Port Forwards')
      show_port_forwards(client: client, anon: anon)

      report_header('Routes & Dynamic DNS')
      show_routes(client: client, anon: anon)

      report_header('DHCP Networks')
      show_dhcp(client: client, anon: anon)

      report_header('DHCP Leases & Reservations')
      show_dhcp_leases(client: client, anon: anon)

      report_header('Power (PoE)')
      show_power(client: client, anon: anon)

      report_header('Ports')
      show_ports(client: client, anon: anon)

      report_header('Port Errors')
      show_port_errors(client: client, anon: anon)

      report_header('Administrators')
      show_admins(client: client, anon: anon)

      report_header('Site Settings')
      show_settings(client: client, anon: anon)

      report_header('Alarms')
      show_alarms(client: client, anon: anon)

      report_header('IDS/IPS Detections')
      show_threats(client: client, anon: anon)
    end

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    private

    # Resolves an --api-key value: "-" reads the key from a hidden prompt (or
    # stdin when piped) so it never appears in shell history or `ps` output.
    def read_api_key(value)
      return validated_api_key(value) unless value == '-'

      key = ($stdin.tty? ? IO.console.getpass('API key: ') : $stdin.gets.to_s).chomp
      abort 'No API key provided.' if key.empty?
      validated_api_key(key)
    end

    # A control character in the key would be rejected by the transport anyway;
    # catching it here says so while the user is still at the prompt.
    def validated_api_key(key)
      abort 'API key must not contain control characters.' if key.match?(/[[:cntrl:]]/)
      key
    end

    # How an unset/true/false policy value reads in output. Unset is a real
    # third state: the audit reports the controller's setting but does not
    # call it right or wrong.
    def policy_label(value)
      case value
      when true  then 'expected'
      when false then 'not expected'
      else 'unset'
      end
    end

    # Whether this network is supposed to have controller remote/cloud access
    # enabled. The audit only reports the controller's actual setting as a
    # finding when it disagrees with this, so the answer has to come from the
    # operator rather than a built-in assumption.
    def remote_access_policy
      return options[:remote_access] unless options[:remote_access].nil?

      unless $stdin.tty?
        say 'Remote access policy left unset — set it with `ui-manage policy --remote-access` ' \
            'or `--no-remote-access`.'
        return nil
      end

      say ''
      say 'Audit policy: should this controller be reachable through UniFi remote (cloud) access?'
      say 'Answer no unless you deliberately manage this network from outside it — the audit'
      say 'reports a finding whenever the controller disagrees with your answer.'
      yes?('Remote access expected? [y/N]')
    end

    def resolve_client
      config = Config.new

      dev = begin
        config.device(options[:device])
      rescue => e
        abort e.message
      end

      abort 'No devices configured. Run `ui-manage login HOST` to add one.' if dev.nil?

      creds =
        if dev['encrypted_api_key']
          { api_key: Encryption.decrypt(dev['encrypted_api_key']) }
        else
          { username: dev['username'], password: Encryption.decrypt(dev['encrypted_password']) }
        end

      Client.new(
        host:       dev['host'],
        site:       dev['site'] || 'default',
        verify_ssl: !!dev['verify_ssl'],
        verbose:    options[:verbose],
        **creds
      )
    rescue ArgumentError, OpenSSL::OpenSSLError => e
      abort "Could not decrypt stored credentials for '#{dev['name']}' (#{e.message}). " \
            'Re-run `ui-manage login` for this device.'
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
        title: 'Firewall Rules',
        sort:  options[:sort]
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
        title: 'Port Forwarding Rules',
        sort:  options[:sort]
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
        title: options[:all] ? 'Networks' : 'DHCP Networks',
        sort:  options[:sort]
      )
    end

    def show_dhcp_leases(client: nil, anon: Anonymizer.new(false))
      clients = with_client(client) { |c| c.dhcp_leases }

      return Formatter.json(anon.deep_scrub(clients)) if options[:json]

      reservations = clients.select { |c| c['use_fixedip'] }
      leases       = clients.select { |c| !c['use_fixedip'] && c['ip'] }
                            .sort_by { |c| ip_sort_key(c['ip']) }

      lease_table(reservations, anon, title: 'Static Reservations', ip_header: 'Reserved IP', ip_key: 'fixed_ip')
      lease_table(leases,       anon, title: 'Dynamic Leases',      ip_header: 'IP',          ip_key: 'ip')

      say 'No leases or reservations found.' if reservations.empty? && leases.empty?
    end

    def lease_table(clients, anon, title:, ip_header:, ip_key:)
      return if clients.empty?

      rows = clients.map do |c|
        [
          c['name'] || c['hostname'] || '—',
          anon.mac(c['mac']),
          anon.ip(c[ip_key]),
          c['oui'] || '—',
          format_last_seen(c['last_seen'])
        ]
      end
      Formatter.table(['Name', 'MAC', ip_header, 'Vendor', 'Last Seen'], rows, title: title, sort: options[:sort])
    end

    def show_power(client: nil, anon: Anonymizer.new(false))
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
        title: 'PoE Port Power',
        sort:  options[:sort]
      )
    end

    # Turns PoE on/off for a single port, identified as "DEVICE:PORT" where
    # DEVICE is a device's full name or a unique substring of one.
    def toggle_port_power(spec, enabled:)
      pattern, _, port_str = spec.rpartition(':')
      abort 'Expected "DEVICE:PORT" (e.g. "Living Room:3").' if pattern.empty? || port_str.empty?

      port_idx = Integer(port_str, exception: false)
      abort "Invalid port number: #{port_str.inspect}" unless port_idx

      client = resolve_client

      with_client(client) do |c|
        dev  = find_device_by_pattern(c.devices, pattern)
        name = dev['name'] || dev['model']

        port = (dev['port_table'] || []).find { |p| p['port_idx'] == port_idx }
        abort "Port #{port_idx} not found on #{name}." unless port
        abort "Port #{port_idx} on #{name} does not support PoE." unless port['poe_caps'].to_i > 0

        c.set_port_poe(device: dev, port_idx: port_idx, enabled: enabled)

        label = port['name'] ? "port #{port_idx} (#{port['name']})" : "port #{port_idx}"
        say "Turned PoE #{enabled ? 'on' : 'off'} for #{name} #{label}."
      end
    end

    # Matches a device by its full name, or by a substring of its name if
    # exactly one device contains it.
    def find_device_by_pattern(devs, pattern)
      exact = devs.find { |d| d['name'] == pattern }
      return exact if exact

      matches = devs.select { |d| d['name']&.downcase&.include?(pattern.downcase) }
      case matches.size
      when 0
        abort "No device matches #{pattern.inspect}."
      when 1
        matches.first
      else
        names = matches.map { |d| d['name'] || d['model'] }.join(', ')
        abort "#{pattern.inspect} matches multiple devices (#{names}) — use a more specific pattern."
      end
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
        title: 'Ports',
        sort:  options[:sort]
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
        title: 'Storage',
        sort:  options[:sort]
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

    def show_clients(client: nil, anon: Anonymizer.new(false), pattern: nil)
      client ||= resolve_client
      devs, sta = with_client(client) { |c| [c.devices, c.clients] }

      if pattern
        needle = pattern.downcase
        sta = sta.select { |c| [c['name'], c['hostname'], c['ip']].any? { |v| v.to_s.downcase.include?(needle) } }
      end

      sta = sta.select { |c| c['is_wired'] }         if options[:wired]
      sta = sta.reject { |c| c['is_wired'] }         if options[:wireless]
      sta = sta.select { |c| c['name'].to_s.empty? } if options[:unknown]
      sta = sta.select { |c| c['is_guest'] }         if options[:guest]
      sta = select_recent(sta, options[:since])
      sta = select_vlan(sta, options[:vlan], client)

      return Formatter.json(anon.deep_scrub(sta)) if options[:json]

      if sta.empty?
        say pattern ? "No clients match #{pattern.inspect}." : 'No clients found.'
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
        title: "Clients (#{rows.size})",
        sort:  options[:sort]
      )
    end

    # Clients first seen within the last +hours+. `first_seen` is when the
    # controller met the device, not when it last connected, so this
    # answers "what is new here" rather than "what is online".
    def select_recent(clients, hours)
      return clients if hours.nil?

      cutoff = Time.now.to_i - (hours.to_i * 3600)
      clients.select { |c| c['first_seen'].to_i >= cutoff }
    end

    # Clients on a given VLAN. Networks without a tag report no vlan at
    # all, so they answer to 0.
    def select_vlan(clients, vlan, client)
      return clients if vlan.nil?

      ids = with_client(client) { |c| c.networks }
            .select { |n| n['vlan'].to_i == vlan.to_i }
            .map { |n| n['_id'] }
      clients.select { |c| ids.include?(c['network_id']) }
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
