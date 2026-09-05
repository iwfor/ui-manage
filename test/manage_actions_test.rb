require_relative 'test_helper'

module UiManage
  class ManageActionsTest < TestCase
    NETWORKS = 'rest/networkconf'.freeze
    WLANS    = 'rest/wlanconf'.freeze
    USERS    = 'rest/user'.freeze
    ZONES    = 'firewall/zone'.freeze

    def networks
      [
        { '_id' => 'wan1', 'name' => 'Internet 1', 'purpose' => 'wan' },
        { '_id' => 'lan',  'name' => 'Default', 'purpose' => 'corporate', 'ip_subnet' => '192.168.1.1/24',
          'attr_no_delete' => true },
        { '_id' => 'iot',  'name' => 'IoT', 'purpose' => 'corporate', 'vlan' => 30, 'vlan_enabled' => true,
          'ip_subnet' => '192.168.30.1/24' },
        { '_id' => 'lab',  'name' => 'Lab', 'purpose' => 'corporate', 'vlan' => 40, 'ip_subnet' => '10.0.40.1/24' }
      ]
    end

    def zones
      [
        { '_id' => 'z-int', 'name' => 'Internal', 'zone_key' => 'internal', 'network_ids' => %w[lan iot] },
        { '_id' => 'z-hot', 'name' => 'Hotspot',  'zone_key' => 'hotspot',  'network_ids' => [] }
      ]
    end

    def wlans
      [
        { '_id' => 'w1', 'name' => 'Home',  'networkconf_id' => 'lan', 'is_guest' => false },
        { '_id' => 'w2', 'name' => 'HomeGuest', 'networkconf_id' => 'lan', 'is_guest' => false }
      ]
    end

    def users
      [
        { '_id' => 'u1', 'mac' => 'aa:bb:cc:dd:ee:01', 'name' => 'Living Room TV', 'is_wired' => false,
          'last_ip' => '192.168.1.50', 'virtual_network_override_enabled' => false },
        { '_id' => 'u2', 'mac' => 'aa:bb:cc:dd:ee:02', 'hostname' => 'printer', 'is_wired' => true,
          'last_ip' => '192.168.1.51', 'ip' => '192.168.1.51',
          'virtual_network_override_enabled' => true,
          'virtual_network_override_id' => 'iot', 'last_seen' => Time.now.to_i },
        { '_id' => 'u3', 'mac' => 'aa:bb:cc:dd:ee:03', 'name' => 'Living Room Lamp', 'is_wired' => false,
          'use_fixedip' => true, 'fixed_ip' => '192.168.1.60', 'network_id' => 'lan' }
      ]
    end

    def routes(extra = {})
      { NETWORKS => networks, ZONES => zones, WLANS => wlans, USERS => users }.merge(extra)
    end

    def writes(requests) = requests.reject { |r| r.method == :get }

    # --- vlan-create ----------------------------------------------------------

    def test_vlan_create_posts_a_full_network_record
      # The controller answers a POST with the record it stored.
      answer = ->(req) { req.method == :post ? [req.json_body.merge('_id' => 'new')] : networks }
      out, requests, status = perform(:vlan_create, routes(NETWORKS => answer), args: ['Cameras'],
                                                                                 vlan: 50, subnet: '10.0.50.0/24')

      assert_equal 0, status
      post = writes(requests).first
      assert_equal :post, post.method
      assert_match %r{/rest/networkconf\z}, post.path
      body = post.json_body
      assert_equal 'Cameras',       body['name']
      assert_equal 50,              body['vlan']
      assert_equal '10.0.50.1/24',  body['ip_subnet']
      assert_equal 'corporate',     body['purpose']
      assert_equal '10.0.50.6',     body['dhcpd_start']
      refute body.key?('firewall_zone_id')
      assert_includes out, "Created network 'Cameras' (VLAN 50, 10.0.50.1/24)"
    end

    def test_vlan_create_guest_lands_in_the_hotspot_zone_without_isolation
      out, requests, = perform(:vlan_create, routes, args: ['Guest'], vlan: 20, subnet: '192.168.20.1/24', guest: true)

      body = writes(requests).first.json_body
      assert_equal 'z-hot',     body['firewall_zone_id']
      # The controller rejects "Isolate Network" on a guest network, and
      # rewrites the purpose to guest itself for a Hotspot-zone network.
      assert_equal false,       body['network_isolation_enabled']
      assert_equal 'corporate', body['purpose']
      assert_equal true,        body['dhcpd_enabled'], 'an unset --dhcp flag leaves DHCP on'
      assert_equal true,        body['internet_access_enabled']
      assert_includes out, 'in the Hotspot zone'
    end

    def test_vlan_create_guest_falls_back_to_the_legacy_purpose_without_zones
      _, requests, = perform(:vlan_create, routes(ZONES => 404), args: ['Guest'], vlan: 20,
                                                                   subnet: '192.168.20.1/24', guest: true)

      body = writes(requests).first.json_body
      assert_equal 'guest', body['purpose']
      refute body.key?('firewall_zone_id')
    end

    def test_vlan_create_refuses_a_zone_the_controller_lacks
      out, requests, status = perform(:vlan_create, routes(ZONES => 404), args: ['X'], vlan: 21,
                                                                          subnet: '10.0.21.1/24', zone: 'dmz')

      assert_equal 1, status
      assert_empty writes(requests)
      assert_includes out, 'no firewall zones'
    end

    def test_vlan_create_refuses_a_taken_vlan_or_name_before_writing
      out, requests, status = perform(:vlan_create, routes, args: ['Cameras'], vlan: 30, subnet: '10.0.50.1/24')
      assert_equal 1, status
      assert_empty writes(requests)
      assert_includes out, "VLAN 30 is already used by 'IoT'"

      out, requests, status = perform(:vlan_create, routes, args: ['IoT'], vlan: 31, subnet: '10.0.50.1/24')
      assert_equal 1, status
      assert_empty writes(requests)
      assert_includes out, 'already exists'
    end

    def test_vlan_create_reports_a_bad_subnet_without_writing
      out, requests, status = perform(:vlan_create, routes, args: ['X'], vlan: 31, subnet: 'garbage')

      assert_equal 1, status
      assert_empty writes(requests)
      assert_includes out, 'Subnet'
    end

    # --- vlan-set -------------------------------------------------------------

    def test_vlan_set_sends_only_the_changed_fields
      out, requests, = perform(:vlan_set, routes, args: ['IoT'], isolate: true, internet: false)

      put = writes(requests).first
      assert_equal :put, put.method
      assert_match %r{/rest/networkconf/iot\z}, put.path
      assert_equal({ 'network_isolation_enabled' => true, 'internet_access_enabled' => false }, put.json_body)
      assert_includes out, "Updated network 'IoT'"
    end

    def test_vlan_set_moves_the_network_into_a_zone_by_name
      _, requests, = perform(:vlan_set, routes, args: ['Lab'], zone: 'Hotspot')

      assert_equal({ 'firewall_zone_id' => 'z-hot' }, writes(requests).first.json_body)
    end

    def test_vlan_set_checks_a_range_against_the_existing_subnet
      out, requests, status = perform(:vlan_set, routes, args: ['Lab'], dhcp_range: '192.168.30.10-192.168.30.20')
      assert_equal 1, status
      assert_empty writes(requests)
      assert_includes out, 'outside 10.0.40.1/24'

      _, requests, = perform(:vlan_set, routes, args: ['Lab'], dhcp_range: '10.0.40.10-10.0.40.20')
      assert_equal({ 'dhcpd_start' => '10.0.40.10', 'dhcpd_stop' => '10.0.40.20' }, writes(requests).first.json_body)
    end

    def test_vlan_set_with_nothing_to_change_says_so
      out, requests, status = perform(:vlan_set, routes, args: ['IoT'])

      assert_equal 1, status
      assert_empty writes(requests)
      assert_includes out, 'Nothing to change'
    end

    def test_vlan_set_matches_a_unique_fragment_but_not_an_ambiguous_one
      _, requests, = perform(:vlan_set, routes, args: ['io'], isolate: true)
      assert_match %r{/iot\z}, writes(requests).first.path

      out, requests, status = perform(:vlan_set, routes, args: ['a'], isolate: true)
      assert_equal 1, status
      assert_empty writes(requests)
      assert_includes out, 'matches multiple'
    end

    def test_vlan_set_never_touches_a_wan_network
      out, requests, status = perform(:vlan_set, routes, args: ['Internet 1'], isolate: true)

      assert_equal 1, status
      assert_empty writes(requests)
      assert_includes out, 'No network matches'
    end

    # --- vlan-delete ----------------------------------------------------------

    def test_vlan_delete_deletes_an_unused_network
      out, requests, status = perform(:vlan_delete, routes, args: ['Lab'], yes: true)

      assert_equal 0, status
      del = writes(requests).first
      assert_equal :delete, del.method
      assert_match %r{/rest/networkconf/lab\z}, del.path
      assert_includes out, "Deleted network 'Lab'"
    end

    def test_vlan_delete_refuses_a_network_still_in_use
      out, requests, status = perform(:vlan_delete, routes, args: ['IoT'], yes: true)

      assert_equal 1, status
      assert_empty writes(requests)
      assert_includes out, 'still in use'
      assert_includes out, 'printer'
    end

    def test_vlan_delete_refuses_a_network_a_wlan_uses
      out, requests, status = perform(:vlan_delete, routes, args: ['Default'], yes: true)

      assert_equal 1, status
      assert_empty writes(requests)
      assert_includes out, 'built-in'
    end

    def test_vlan_delete_needs_yes_without_a_terminal
      $stdin.stub(:tty?, false) do
        out, requests, status = perform(:vlan_delete, routes, args: ['Lab'])

        assert_equal 1, status
        assert_empty writes(requests)
        assert_includes out, '--yes'
      end
    end

    # --- pin / unpin / pins ---------------------------------------------------

    def test_pin_sets_the_network_override_by_vlan
      out, requests, status = perform(:pin, routes, args: ['Living Room TV'], vlan: 30)

      assert_equal 0, status
      put = writes(requests).first
      assert_match %r{/rest/user/u1\z}, put.path
      assert_equal({ 'virtual_network_override_enabled' => true, 'virtual_network_override_id' => 'iot' }, put.json_body)
      assert_includes out, "Pinned 'Living Room TV' (aa:bb:cc:dd:ee:01) to 'IoT' (VLAN 30)"
    end

    def test_pin_finds_a_client_by_mac_ip_or_unique_name_fragment
      _, requests, = perform(:pin, routes, args: ['AA:BB:CC:DD:EE:03'], network: 'Lab')
      assert_match %r{/u3\z}, writes(requests).first.path

      _, requests, = perform(:pin, routes, args: ['192.168.1.51'], network: 'Lab')
      assert_match %r{/u2\z}, writes(requests).first.path

      _, requests, = perform(:pin, routes, args: ['lamp'], network: 'Lab')
      assert_match %r{/u3\z}, writes(requests).first.path

      out, requests, status = perform(:pin, routes, args: ['living room'], network: 'Lab')
      assert_equal 1, status
      assert_empty writes(requests)
      assert_includes out, 'matches multiple'
    end

    def test_pin_warns_that_a_wired_client_needs_a_trunk_port
      out, = perform(:pin, routes, args: ['printer'], vlan: 40)

      assert_includes out, 'switch port carries that VLAN'
    end

    def test_pin_needs_exactly_one_target
      out, requests, status = perform(:pin, routes, args: ['printer'])
      assert_equal 1, status
      assert_empty writes(requests)
      assert_includes out, '--vlan N or --network NAME'

      out, requests, status = perform(:pin, routes, args: ['printer'], vlan: 30, network: 'IoT')
      assert_equal 1, status
      assert_empty writes(requests)
      assert_includes out, 'not both'

      out, requests, status = perform(:pin, routes, args: ['printer'], vlan: 99)
      assert_equal 1, status
      assert_empty writes(requests)
      assert_includes out, 'No network uses VLAN 99'
    end

    def test_unpin_clears_the_override
      out, requests, status = perform(:unpin, routes, args: ['printer'])

      assert_equal 0, status
      put = writes(requests).first
      assert_match %r{/rest/user/u2\z}, put.path
      assert_equal({ 'virtual_network_override_enabled' => false, 'virtual_network_override_id' => '' }, put.json_body)
      assert_includes out, 'Unpinned'
    end

    def test_unpin_on_an_unpinned_client_changes_nothing
      out, requests, = perform(:unpin, routes, args: ['Living Room TV'])

      assert_empty writes(requests)
      assert_includes out, 'is not pinned'
    end

    def test_pins_lists_pinned_clients_with_their_network
      out = render(:pins, routes)

      assert_includes out, 'printer'
      assert_includes out, 'IoT (VLAN 30)'
      refute_includes out, 'Living Room TV'
    end

    def test_pins_json_and_anon
      out = render(:pins, routes, json: true)
      assert_equal 1, JSON.parse(out).size

      out = render(:pins, routes, anon: true)
      refute_includes out, 'aa:bb:cc:dd:ee:02'
      refute_includes out, 'printer'
    end

    # --- client-set -----------------------------------------------------------

    def test_client_set_names_a_client
      out, requests, status = perform(:client_set, routes, args: ['aa:bb:cc:dd:ee:02'], name: 'Office Printer')

      assert_equal 0, status
      put = writes(requests).first
      assert_equal :put, put.method
      assert_match %r{/rest/user/u2\z}, put.path
      assert_equal({ 'name' => 'Office Printer', 'noted' => true }, put.json_body)
      assert_includes out, %{Renamed 'printer' (aa:bb:cc:dd:ee:02) to "Office Printer"}
    end

    def test_client_set_renames_a_client_that_already_has_a_name
      out, requests, = perform(:client_set, routes, args: ['Living Room TV'], name: 'Den TV')

      assert_equal 'Den TV', writes(requests).first.json_body['name']
      assert_includes out, %{Renamed 'Living Room TV' (aa:bb:cc:dd:ee:01) to "Den TV"}
    end

    def test_client_set_clears_a_name_and_unsets_noted
      out, requests, status = perform(:client_set, routes, args: ['Living Room TV'], name: '')

      assert_equal 0, status
      assert_equal({ 'name' => '', 'noted' => false }, writes(requests).first.json_body)
      assert_includes out, 'Cleared the name'
    end

    def test_client_set_leaves_an_unchanged_name_alone
      out, requests, = perform(:client_set, routes, args: ['Living Room Lamp'], name: 'Living Room Lamp')

      assert_empty writes(requests)
      assert_includes out, 'already named'
    end

    def test_client_set_needs_a_setting_to_set
      out, requests, status = perform(:client_set, routes, args: ['printer'])

      assert_equal 1, status
      assert_empty writes(requests)
      assert_includes out, 'Nothing to change'
    end

    # --- reserve / unreserve --------------------------------------------------

    def test_reserve_sets_a_fixed_ip_on_the_network_holding_it
      out, requests, status = perform(:reserve, routes, args: ['Living Room TV', '192.168.30.10'])

      assert_equal 0, status
      put = writes(requests).first
      assert_equal :put, put.method
      assert_match %r{/rest/user/u1\z}, put.path
      assert_equal({ 'use_fixedip' => true, 'fixed_ip' => '192.168.30.10', 'network_id' => 'iot' }, put.json_body)
      assert_includes out, "Reserved 192.168.30.10 for 'Living Room TV' (aa:bb:cc:dd:ee:01) on 'IoT'"
    end

def test_reserve_reports_the_address_it_replaced
out, requests, status = perform(:reserve, routes, args: ["Living Room Lamp", "192.168.1.61"])

assert_equal 0, status
assert_equal "192.168.1.61", writes(requests).first.json_body["fixed_ip"]
assert_includes out, "(was 192.168.1.60)"
end

    def test_reserve_refuses_an_address_outside_every_network
      out, requests, status = perform(:reserve, routes, args: ['printer', '172.16.0.5'])

      assert_equal 1, status
      assert_empty writes(requests)
      assert_includes out, 'not inside any of your networks'
    end

    def test_reserve_refuses_an_address_that_is_not_an_ipv4_address
      out, requests, status = perform(:reserve, routes, args: ['printer', 'garbage'])

      assert_equal 1, status
      assert_empty writes(requests)
      assert_includes out, 'not an IPv4 address'
    end

    def test_reserve_refuses_the_gateway_network_and_broadcast_addresses
      %w[192.168.30.1 192.168.30.0 192.168.30.255].each do |address|
        out, requests, status = perform(:reserve, routes, args: ['printer', address])

        assert_equal 1, status, address
        assert_empty writes(requests), address
        assert_match(/gateway address|network address|broadcast address/, out)
      end
    end

    def test_reserve_refuses_an_address_another_client_already_reserves
      out, requests, status = perform(:reserve, routes, args: ['Living Room TV', '192.168.1.60'])

      assert_equal 1, status
      assert_empty writes(requests)
      assert_includes out, 'already reserved for'
      assert_includes out, 'aa:bb:cc:dd:ee:03'
    end

    def test_reserve_leaves_an_unchanged_reservation_alone
      out, requests, = perform(:reserve, routes, args: ['Living Room Lamp', '192.168.1.60'])

      assert_empty writes(requests)
      assert_includes out, 'already reserves'
    end

    # The controller leaves `network_id` unset on a reservation made through
    # its own UI, and `dhcp_reservation` needs it to range-check one.
    def test_reserve_records_the_network_on_a_reservation_that_lacks_one
      users_without_network = users.map { |u| u['_id'] == 'u3' ? u.reject { |k, _| k == 'network_id' } : u }
      out, requests, status = perform(:reserve, routes(USERS => users_without_network),
                                      args: ['Living Room Lamp', '192.168.1.60'])

      assert_equal 0, status
      assert_equal({ 'use_fixedip' => true, 'fixed_ip' => '192.168.1.60', 'network_id' => 'lan' },
                   writes(requests).first.json_body)
      assert_includes out, 'recording the network it belongs to'
      refute_includes out, '(was '
    end

    def test_reserve_warns_when_another_client_holds_the_address_dynamically
      out, requests, = perform(:reserve, routes, args: ['Living Room TV', '192.168.1.51'])

      refute_empty writes(requests)
      assert_includes out, 'dynamic lease'
      assert_includes out, 'printer'
    end

    def test_reserve_uses_the_named_network_and_checks_the_address_against_it
      out, requests, status = perform(:reserve, routes, args: ['printer', '192.168.30.10'], network: 'Default')

      assert_equal 1, status
      assert_empty writes(requests)
      assert_includes out, "outside 'Default'"
    end

    def test_unreserve_clears_the_fixed_ip
      out, requests, status = perform(:unreserve, routes, args: ['Living Room Lamp'])

      assert_equal 0, status
      put = writes(requests).first
      assert_match %r{/rest/user/u3\z}, put.path
      assert_equal({ 'use_fixedip' => false }, put.json_body)
      assert_includes out, 'Released 192.168.1.60'
    end

    def test_unreserve_on_a_client_without_one_changes_nothing
      out, requests, = perform(:unreserve, routes, args: ['printer'])

      assert_empty writes(requests)
      assert_includes out, 'no reserved address'
    end

    # --- wlan-set -------------------------------------------------------------

    def test_wlan_set_makes_an_ssid_a_guest_network
      out, requests, status = perform(:wlan_set, routes, args: ['HomeGuest'], network: 'IoT', guest: true, isolate: true)

      assert_equal 0, status
      put = writes(requests).first
      assert_equal :put, put.method
      assert_match %r{/rest/wlanconf/w2\z}, put.path
      assert_equal({ 'networkconf_id' => 'iot', 'is_guest' => true, 'l2_isolation' => true }, put.json_body)
      assert_includes out, "Updated WLAN 'HomeGuest'"
      assert_includes out, 'network: IoT (VLAN 30)'
    end

    def test_wlan_set_security_and_passphrase_never_echo_the_secret
      out, requests, = perform(:wlan_set, routes, args: ['Home'], security: 'wpa3', passphrase: 'a-new-passphrase')

      body = writes(requests).first.json_body
      assert_equal 'a-new-passphrase', body['x_passphrase']
      assert_equal true, body['wpa3_support']
      assert_equal 'required', body['pmf_mode']
      refute_includes out, 'a-new-passphrase'
      assert_includes out, 'passphrase: updated'
    end

    def test_wlan_set_open_clears_the_passphrase
      _, requests, = perform(:wlan_set, routes, args: ['Home'], security: 'open')

      assert_equal '', writes(requests).first.json_body['x_passphrase']
    end

    def test_wlan_set_reads_the_passphrase_from_stdin_when_piped
      $stdin.stub(:tty?, false) do
        $stdin.stub(:gets, "from-stdin-psk\n") do
          _, requests, = perform(:wlan_set, routes, args: ['Home'], passphrase: '-')

          assert_equal 'from-stdin-psk', writes(requests).first.json_body['x_passphrase']
        end
      end
    end

    def test_wlan_set_refuses_bad_values_before_writing
      out, requests, status = perform(:wlan_set, routes, args: ['Home'], security: 'wep')
      assert_equal 1, status
      assert_empty writes(requests)
      assert_includes out, 'Security'

      out, requests, status = perform(:wlan_set, routes, args: ['Home'])
      assert_equal 1, status
      assert_empty writes(requests)
      assert_includes out, 'Nothing to change'

      out, requests, status = perform(:wlan_set, routes, args: ['Home'], network: 'Nope')
      assert_equal 1, status
      assert_empty writes(requests)
      assert_includes out, 'No network matches'
    end

    def test_wlan_set_reports_an_unavailable_wlan_list
      out, requests, status = perform(:wlan_set, routes(WLANS => 403), args: ['Home'], guest: true)

      assert_equal 1, status
      assert_empty writes(requests)
      assert_includes out, 'unavailable'
    end

    def test_wlan_set_matches_the_exact_name_over_a_fragment
      _, requests, = perform(:wlan_set, routes, args: ['Home'], hidden: true)

      assert_match %r{/w1\z}, writes(requests).first.path
    end
  end
end
