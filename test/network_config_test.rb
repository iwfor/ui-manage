require_relative 'test_helper'

module UiManage
  class NetworkConfigTest < TestCase
    def test_build_fills_in_the_lan_defaults
      attrs = NetworkConfig.build(name: 'IoT', vlan: 30, subnet: '192.168.30.1/24')

      assert_equal 'IoT',             attrs['name']
      assert_equal 30,                attrs['vlan']
      assert_equal true,              attrs['vlan_enabled']
      assert_equal '192.168.30.1/24', attrs['ip_subnet']
      assert_equal 'corporate',       attrs['purpose']
      assert_equal 'LAN',             attrs['networkgroup']
      assert_equal true,              attrs['enabled']
      assert_equal true,              attrs['dhcpd_enabled']
      assert_equal '192.168.30.6',    attrs['dhcpd_start']
      assert_equal '192.168.30.254',  attrs['dhcpd_stop']
      assert_equal false,             attrs['network_isolation_enabled']
      assert_equal true,              attrs['internet_access_enabled']
      refute attrs.key?('firewall_zone_id')
    end

    def test_unset_flags_take_the_lan_defaults
      attrs = NetworkConfig.build(name: 'IoT', vlan: 30, subnet: '192.168.30.1/24',
                                  purpose: nil, dhcp: nil, isolate: nil, internet: nil)

      assert_equal 'corporate', attrs['purpose']
      assert_equal true,        attrs['dhcpd_enabled']
      assert_equal false,       attrs['network_isolation_enabled']
      assert_equal true,        attrs['internet_access_enabled']
    end

    def test_a_network_address_becomes_the_first_usable_gateway
      attrs = NetworkConfig.build(name: 'Guest', vlan: 20, subnet: '192.168.20.0/24')

      assert_equal '192.168.20.1/24', attrs['ip_subnet']
      assert_equal '192.168.20.6',    attrs['dhcpd_start']
    end

    def test_a_gateway_address_is_kept_as_given
      attrs = NetworkConfig.build(name: 'Lab', vlan: 5, subnet: '10.0.5.254/24')

      assert_equal '10.0.5.254/24', attrs['ip_subnet']
      assert_equal %w[10.0.5.1 10.0.5.253], attrs.values_at('dhcpd_start', 'dhcpd_stop'), 'pool falls below a gateway at the top'
    end

    def test_an_explicit_dhcp_range_is_checked_against_the_subnet
      attrs = NetworkConfig.build(name: 'Lab', vlan: 5, subnet: '10.0.5.1/24', dhcp_range: '10.0.5.50-10.0.5.99')
      assert_equal %w[10.0.5.50 10.0.5.99], attrs.values_at('dhcpd_start', 'dhcpd_stop')

      error = assert_raises(NetworkConfig::Invalid) do
        NetworkConfig.build(name: 'Lab', vlan: 5, subnet: '10.0.5.1/24', dhcp_range: '10.0.6.50-10.0.6.99')
      end
      assert_includes error.message, 'outside 10.0.5.1/24'

      assert_raises(NetworkConfig::Invalid) do
        NetworkConfig.build(name: 'Lab', vlan: 5, subnet: '10.0.5.1/24', dhcp_range: '10.0.5.99-10.0.5.50')
      end
    end

    def test_a_small_subnet_still_gets_a_pool
      attrs = NetworkConfig.build(name: 'Tiny', vlan: 9, subnet: '10.9.9.1/30')

      assert_equal '10.9.9.2', attrs['dhcpd_start']
      assert_equal '10.9.9.2', attrs['dhcpd_stop']
    end

    def test_guest_purpose_isolation_internet_and_zone_are_written
      attrs = NetworkConfig.build(name: 'Guest', vlan: 20, subnet: '192.168.20.1/24', purpose: 'guest',
                                  isolate: true, internet: false, dhcp: false, zone_id: 'zone1')

      assert_equal 'guest', attrs['purpose']
      assert_equal true,    attrs['network_isolation_enabled']
      assert_equal false,   attrs['internet_access_enabled']
      assert_equal false,   attrs['dhcpd_enabled']
      assert_equal 'zone1', attrs['firewall_zone_id']
    end

    def test_attributes_only_carries_what_was_given
      assert_equal({}, NetworkConfig.attributes)
      assert_equal({ 'name' => 'New' }, NetworkConfig.attributes(name: 'New'))
      assert_equal({ 'network_isolation_enabled' => false }, NetworkConfig.attributes(isolate: false))
    end

    def test_a_new_subnet_moves_the_dhcp_pool_with_it
      attrs = NetworkConfig.attributes(subnet: '10.0.7.1/24')

      assert_equal '10.0.7.6',   attrs['dhcpd_start']
      assert_equal '10.0.7.254', attrs['dhcpd_stop']
    end

    def test_a_range_on_its_own_is_checked_against_the_existing_subnet
      assert_equal %w[10.0.7.10 10.0.7.20], NetworkConfig.range_for('10.0.7.10-10.0.7.20', '10.0.7.1/24')
      assert_raises(NetworkConfig::Invalid) { NetworkConfig.range_for('10.0.8.10-10.0.8.20', '10.0.7.1/24') }
    end

    def test_bad_values_are_refused_with_a_reason
      assert_includes refused { NetworkConfig.build(name: '', vlan: 1, subnet: '10.0.0.1/24') }, 'name'
      assert_includes refused { NetworkConfig.build(name: 'x', vlan: 0, subnet: '10.0.0.1/24') }, 'VLAN'
      assert_includes refused { NetworkConfig.build(name: 'x', vlan: 4095, subnet: '10.0.0.1/24') }, 'VLAN'
      assert_includes refused { NetworkConfig.build(name: 'x', vlan: 1, subnet: '10.0.0.1') }, 'ADDRESS/PREFIX'
      assert_includes refused { NetworkConfig.build(name: 'x', vlan: 1, subnet: 'nope/24') }, 'IPv4'
      assert_includes refused { NetworkConfig.build(name: 'x', vlan: 1, subnet: '10.0.0.1/31') }, 'prefix'
      assert_includes refused { NetworkConfig.build(name: 'x', vlan: 1, subnet: '10.0.0.1/24', purpose: 'wan') }, 'Purpose'
      assert_includes refused { NetworkConfig.build(name: 'x', vlan: 1, subnet: '10.0.0.1/24', dhcp_range: '10.0.0.5') }, 'START-STOP'
    end

    private

    def refused
      assert_raises(NetworkConfig::Invalid) { yield }.message
    end
  end
end
