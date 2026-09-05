require 'ipaddr'

module UiManage
  # Turns the options a user gives for a network (VLAN) into the attribute
  # hash the controller stores, and checks them before anything is sent.
  #
  # Pure functions with no controller access, so the rules — what a subnet
  # must look like, where a DHCP range may fall, which purpose a network may
  # have — can be tested on their own and the CLI stays a thin layer over
  # them. #build produces the full record for a create; #attributes produces
  # only the fields that were given, which is what a partial update sends.
  module NetworkConfig
    class Invalid < ArgumentError; end

    # Purposes a user may ask for. `wan` and the VPN purposes exist too, but
    # those networks are created elsewhere and this tool does not make them.
    PURPOSES = %w[corporate guest].freeze

    VLAN_RANGE = (1..4094)

    # UniFi's own default: the DHCP pool starts a few addresses above the
    # gateway and runs to the last usable address.
    DHCP_OFFSET = 5

    module_function

    # Full attribute set for a new network. Everything not given (nil, as an
    # unset command-line flag arrives) takes the controller's own default for
    # a LAN: DHCP on, internet on, not isolated.
    def build(name:, vlan:, subnet:, purpose: nil, dhcp: nil, dhcp_range: nil,
              isolate: nil, internet: nil, zone_id: nil)
      validate_name!(name)
      given = attributes(name: name, vlan: vlan, subnet: subnet, purpose: purpose || 'corporate',
                         dhcp: dhcp.nil? || dhcp, dhcp_range: dhcp_range, isolate: !!isolate,
                         internet: internet.nil? || internet, zone_id: zone_id)

      {
        'enabled'                   => true,
        'networkgroup'              => 'LAN',
        'is_nat'                    => true,
        'dhcpd_leasetime'           => 86_400,
        'dhcpd_dns_enabled'         => false,
        'dhcpd_gateway_enabled'     => false,
        'dhcpd_time_offset_enabled' => false,
        'ipv6_interface_type'       => 'none',
        'ipv6_setting_preference'   => 'auto',
        'setting_preference'        => 'manual',
        'auto_scale_enabled'        => false,
        'igmp_snooping'             => false,
        'mdns_enabled'              => false,
        'upnp_lan_enabled'          => false,
        'dhcpguard_enabled'         => false,
        'lte_lan_enabled'           => true,
        'gateway_type'              => 'default'
      }.merge(given)
    end

    # Only the fields for the options actually given (nil means "not given"),
    # mapped to the controller's names. A subnet change without a DHCP range
    # also moves the pool, because the old pool would fall outside the new
    # subnet and the controller would reject the update.
    def attributes(name: nil, vlan: nil, subnet: nil, purpose: nil, dhcp: nil, dhcp_range: nil,
                   isolate: nil, internet: nil, zone_id: nil)
      attrs = {}
      attrs['name'] = name unless name.nil?

      unless vlan.nil?
        attrs['vlan_enabled'] = true
        attrs['vlan']         = validated_vlan(vlan)
      end

      unless subnet.nil?
        cidr = normalize_subnet(subnet)
        attrs['ip_subnet'] = cidr
        start, stop = dhcp_range ? parse_dhcp_range(dhcp_range, cidr) : default_dhcp_range(cidr)
        attrs['dhcpd_start'] = start
        attrs['dhcpd_stop']  = stop
      end

      if dhcp_range && subnet.nil?
        # Without the subnet, the range is validated later against the
        # network's existing subnet — see #range_for.
        attrs['dhcpd_start'], attrs['dhcpd_stop'] = split_range(dhcp_range)
      end

      attrs['dhcpd_enabled']             = !!dhcp unless dhcp.nil?
      attrs['purpose']                   = validated_purpose(purpose) unless purpose.nil?
      attrs['network_isolation_enabled'] = !!isolate unless isolate.nil?
      attrs['internet_access_enabled']   = !!internet unless internet.nil?
      attrs['firewall_zone_id']          = zone_id unless zone_id.nil?
      attrs
    end

    # A DHCP range given on its own, checked against the subnet the network
    # already has.
    def range_for(dhcp_range, subnet)
      parse_dhcp_range(dhcp_range, normalize_subnet(subnet))
    end

    # The controller stores a network as its gateway address plus prefix:
    # 192.168.20.1/24. Accepts that, or the network address (192.168.20.0/24),
    # in which case the gateway becomes the first usable address.
    def normalize_subnet(value)
      address, prefix = value.to_s.split('/', 2)
      raise Invalid, "Subnet #{value.inspect} must be ADDRESS/PREFIX, e.g. 192.168.20.1/24" if prefix.nil?

      ip = ipv4(address, what: 'Subnet')
      bits = Integer(prefix, exception: false)
      raise Invalid, "Subnet prefix /#{prefix} must be between 8 and 30" unless bits && (8..30).cover?(bits)

      network = IPAddr.new("#{address}/#{bits}")
      gateway = ip == network ? network.succ : ip
      "#{gateway}/#{bits}"
    end

    # The pool runs from a few addresses above the gateway to the last usable
    # address. When the gateway sits at the top of the subnet (or the subnet
    # is too small for the gap), the pool takes whatever usable addresses
    # remain on either side of it instead.
    def default_dhcp_range(cidr)
      gateway      = IPAddr.new(cidr.split('/').first).to_i
      range        = IPAddr.new(cidr).to_range
      first_usable = range.first.to_i + 1
      last_usable  = range.last.to_i - 1

      start, stop =
        if gateway + DHCP_OFFSET <= last_usable then [gateway + DHCP_OFFSET, last_usable]
        elsif gateway < last_usable             then [gateway + 1, last_usable]
        elsif first_usable < gateway            then [first_usable, gateway - 1]
        else raise Invalid, "Subnet #{cidr} has no room for a DHCP pool"
        end

      [start, stop].map { |n| IPAddr.new(n, Socket::AF_INET).to_s }
    end

    # "START-STOP", both inside the subnet and in order.
    def parse_dhcp_range(value, cidr)
      start, stop = split_range(value)
      network     = IPAddr.new(cidr)
      [start, stop].each do |addr|
        raise Invalid, "DHCP address #{addr} is outside #{cidr}" unless network.include?(IPAddr.new(addr))
      end
      raise Invalid, "DHCP range #{value} ends before it starts" if IPAddr.new(start) > IPAddr.new(stop)

      [start, stop]
    end

    def split_range(value)
      start, stop = value.to_s.split('-', 2).map { |s| s.to_s.strip }
      raise Invalid, "DHCP range #{value.inspect} must be START-STOP, e.g. 192.168.20.100-192.168.20.200" if stop.nil?

      [ipv4(start, what: 'DHCP start').to_s, ipv4(stop, what: 'DHCP stop').to_s]
    end

    def validated_vlan(value)
      vlan = Integer(value, exception: false)
      raise Invalid, "VLAN #{value.inspect} must be a number between #{VLAN_RANGE.min} and #{VLAN_RANGE.max}" unless vlan && VLAN_RANGE.cover?(vlan)

      vlan
    end

    def validated_purpose(value)
      purpose = value.to_s.downcase
      raise Invalid, "Purpose #{value.inspect} must be one of #{PURPOSES.join(', ')}" unless PURPOSES.include?(purpose)

      purpose
    end

    def validate_name!(name)
      raise Invalid, 'Network name must not be empty' if name.to_s.strip.empty?
    end

    def ipv4(address, what:)
      ip = IPAddr.new(address.to_s)
      raise Invalid, "#{what} #{address.inspect} is not an IPv4 address" unless ip.ipv4?

      ip
    rescue IPAddr::InvalidAddressError
      raise Invalid, "#{what} #{address.inspect} is not an IPv4 address"
    end
  end
end
