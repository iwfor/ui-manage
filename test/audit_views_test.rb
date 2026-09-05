require_relative 'test_helper'

module UiManage
  class AuditViewsTest < TestCase
    WLAN_PATH    = 'wlanconf'.freeze
    NETWORK_PATH = 'networkconf'.freeze

    def wlan(**overrides)
      { 'name' => 'Home', 'enabled' => true, 'security' => 'wpapsk', 'wpa_mode' => 'wpa2',
        'wpa_enc' => 'ccmp', 'x_passphrase' => 'correcthorsebattery' }.merge(overrides)
    end

    # --- wlans ----------------------------------------------------------------

    def test_wlans_names_the_security_mode
      out = render(:wlans, WLAN_PATH => [wlan])

      assert_includes out, 'WPA2-PSK'
    end

    def test_wlans_labels_wpa3_and_enterprise
      out = render(:wlans, WLAN_PATH => [
                     wlan(name: 'A', 'wpa3_support' => true),
                     wlan(name: 'B', 'security' => 'wpaeap'),
                     wlan(name: 'C', 'wpa3_transition' => true)
                   ])

      assert_includes out, 'WPA3-PSK'
      assert_includes out, 'WPA2-Enterprise'
      assert_includes out, 'WPA3/WPA2-PSK'
    end

    def test_wlans_labels_open_and_wep
      out = render(:wlans, WLAN_PATH => [wlan('security' => 'open'), wlan('security' => 'wep')])

      assert_includes out, 'OPEN'
      assert_includes out, 'WEP'
    end

    # The passphrase is the one thing this command must never print.
    def test_wlans_never_print_the_passphrase
      out = render(:wlans, WLAN_PATH => [wlan])

      refute_includes out, 'correcthorsebattery'
      assert_includes out, 'set (19 chars)'
    end

    def test_wlans_drop_the_passphrase_length_when_anonymising
      out = render(:wlans, { WLAN_PATH => [wlan] }, anon: true)

      refute_includes out, '19 chars'
      assert_includes out, 'set'
    end

    def test_wlans_json_redacts_the_passphrase
      out = render(:wlans, { WLAN_PATH => [wlan] }, json: true)

      refute_includes out, 'correcthorsebattery'
      assert_includes out, Redactor::PLACEHOLDER
    end

    def test_insecure_only_keeps_open_wep_wpa1_tkip_and_wps
      wlans = [
        wlan('name' => 'Open',  'security' => 'open'),
        wlan('name' => 'Wep',   'security' => 'wep'),
        wlan('name' => 'Old',   'wpa_mode' => 'wpa1'),
        wlan('name' => 'Tkip',  'wpa_enc' => 'tkip'),
        wlan('name' => 'Wps',   'wps' => true),
        wlan('name' => 'Fine')
      ]
      out = render(:wlans, { WLAN_PATH => wlans }, insecure_only: true)

      %w[Open Wep Old Tkip Wps].each { |n| assert_includes out, n }
      refute_includes out, 'Fine'
    end

    def test_wlans_resolve_the_network_they_land_on
      out = render(:wlans,
                   WLAN_PATH    => [wlan('networkconf_id' => 'net1')],
                   NETWORK_PATH => [{ '_id' => 'net1', 'name' => 'IoT', 'vlan' => 30 }])

      assert_includes out, 'IoT (VLAN 30)'
    end

    # --- anonymisation ------------------------------------------------------

    # These names have no recognisable shape, so scanning text cannot catch
    # them; they have to be replaced where the field is read.
    def test_anon_replaces_ssids_device_names_and_admin_identities
      assert_includes render(:wlans, { WLAN_PATH => [wlan('name' => 'SmithFamily')] }, anon: true), 'Network-1'
      refute_includes render(:wlans, { WLAN_PATH => [wlan('name' => 'SmithFamily')] }, anon: true), 'SmithFamily'

      admins = render(:admins, { 'stat/admin' => [{ 'name' => 'alice', 'email' => 'alice@corp.test' }] }, anon: true)
      refute_includes admins, 'alice'
      refute_includes admins, 'alice@corp.test'

      as_json = render(:admins, { 'stat/admin' => [{ 'name' => 'alice', 'email' => 'alice@corp.test',
                                                    'ubic_name' => 'alice@corp.test' }] }, anon: true, json: true)
      refute_includes as_json, 'alice'
      assert_includes as_json, 'Person-1'

      firmware = render(:firmware, { 'stat/device' => [{ 'name' => 'AP-Garage' }] }, anon: true)
      refute_includes firmware, 'AP-Garage'
    end

    def test_without_anon_the_real_names_are_shown
      assert_includes render(:wlans, WLAN_PATH => [wlan('name' => 'SmithFamily')]), 'SmithFamily'
    end

    # --- degradation ----------------------------------------------------------

    def test_a_refused_endpoint_says_why_instead_of_aborting
      out = render(:wlans, WLAN_PATH => 403)

      assert_includes out, 'unavailable'
      assert_includes out, 'not permitted'
    end

    def test_a_missing_endpoint_reports_the_controller_version
      out = render(:threats, 'system-log' => 404, 'ips/event' => 404)

      assert_includes out, 'unavailable'
      assert_includes out, 'does not provide it'
    end

    # --- rogue APs ------------------------------------------------------------

    def test_a_neighbour_broadcasting_one_of_our_ssids_is_flagged
      out = render(:rogue_aps,
                   'rogueap' => [{ 'essid' => 'Home', 'bssid' => 'aa:bb:cc:dd:ee:ff', 'channel' => 6 }],
                   WLAN_PATH => [wlan('name' => 'Home')])

      assert_includes out, 'IMPERSONATES'
    end

    def test_an_unrelated_neighbour_is_not_flagged
      out = render(:rogue_aps,
                   'rogueap' => [{ 'essid' => 'Cafe', 'bssid' => 'aa:bb:cc:dd:ee:ff' }],
                   WLAN_PATH => [wlan('name' => 'Home')])

      refute_includes out, 'IMPERSONATES'
    end

    # Without the WLAN list the question is unanswerable — it must not be
    # answered "no", which would read as "checked, and fine".
    def test_impersonation_is_unknown_when_wlans_cannot_be_read
      out = render(:rogue_aps,
                   'rogueap' => [{ 'essid' => 'Home', 'bssid' => 'aa:bb:cc:dd:ee:ff' }],
                   WLAN_PATH => 403)

      refute_includes out, 'IMPERSONATES'
      assert_match(/\|\s+\?\s+\|/, out)
    end

    def test_rogue_aps_filter_by_signal
      routes = { 'rogueap' => [{ 'essid' => 'Near', 'signal' => -50 }, { 'essid' => 'Far', 'signal' => -90 }] }
      out    = render(:rogue_aps, routes, min_signal: -70)

      assert_includes out, 'Near'
      refute_includes out, 'Far'
    end

    # --- admins ---------------------------------------------------------------

    def test_admins_report_two_factor_state
      out = render(:admins, 'stat/admin' => [
                     { 'name' => 'alice', 'x_has_totp' => true },
                     { 'name' => 'bob',   'x_has_totp' => false }
                   ])

      assert_match(/alice.*yes/, out)
      assert_match(/bob.*no/, out)
    end

    # A controller that does not report 2FA must not be read as "no 2FA".
    def test_missing_two_factor_information_reads_as_unknown
      out = render(:admins, 'stat/admin' => [{ 'name' => 'alice', 'role' => 'admin' }])

      assert_includes out, 'unknown'
    end

    def test_the_role_column_is_the_account_s_role_on_this_site
      out = render(:admins, 'stat/admin' => [
                     { 'name' => 'alice', 'roles' => [{ 'site_name' => 'default', 'role' => 'readonly' }] },
                     { 'name' => 'root',  'is_super' => true }
                   ])

      assert_match(/alice.*readonly/, out)
      assert_match(/root.*super.*YES/, out)
    end

    def test_an_api_key_that_cannot_read_admins_says_so
      out = render(:admins, 'stat/admin' => 403)

      assert_includes out, 'unavailable'
      refute_includes out, 'No administrators reported'
    end

    # --- settings -------------------------------------------------------------

    def test_settings_flatten_to_one_row_per_field
      out = render(:settings, 'get/setting' => [{ 'key' => 'mgmt', 'x_ssh_enabled' => true, '_id' => 'a' }])

      assert_includes out, 'mgmt'
      assert_includes out, 'x_ssh_enabled'
      refute_includes out, '_id'
    end

    def test_settings_redact_credentials_in_table_output
      out = render(:settings, 'get/setting' => [{ 'key' => 'mgmt', 'x_ssh_password' => 'hunter2' }])

      refute_includes out, 'hunter2'
      assert_includes out, Redactor::PLACEHOLDER
    end

    def test_settings_filter_by_section
      routes = { 'get/setting' => [{ 'key' => 'mgmt', 'a' => 1 }, { 'key' => 'guest_access', 'b' => 2 }] }
      out    = render(:settings, routes, section: 'guest')

      assert_includes out, 'guest_access'
      refute_includes out, 'mgmt'
    end

    # --- threats --------------------------------------------------------------

    def test_threat_severity_is_named_rather_than_numbered
      out = render(:threats, 'system-log' => [{ 'inner_alert_severity' => 1, 'catname' => 'trojan' }])

      assert_includes out, 'high'
    end

    def test_threats_filter_at_or_above_a_severity
      routes = { 'system-log' => [
        { 'inner_alert_severity' => 1, 'catname' => 'severe' },
        { 'inner_alert_severity' => 3, 'catname' => 'minor' }
      ] }
      out = render(:threats, routes, severity: 'high')

      assert_includes out, 'severe'
      refute_includes out, 'minor'
    end

    def test_an_unknown_severity_is_rejected
      assert_raises(Thor::Error) do
        render(:threats, { 'system-log' => [{ 'inner_alert_severity' => 1 }] }, severity: 'catastrophic')
      end
    end

    # --- events and alarms ----------------------------------------------------

    def test_events_filter_by_type
      routes = { 'system-log' => [
        { 'key' => 'EVT_AD_Login', 'msg' => 'admin logged in' },
        { 'key' => 'EVT_LU_Connected', 'msg' => 'client connected' }
      ] }
      out = render(:events, routes, type: 'login')

      assert_includes out, 'EVT_AD_Login'
      refute_includes out, 'EVT_LU_Connected'
    end

    def test_event_times_render_from_epoch_milliseconds
      ms  = Time.new(2026, 3, 4, 5, 6, 0).to_i * 1000
      out = render(:events, 'system-log' => [{ 'key' => 'EVT_X', 'time' => ms }])

      assert_includes out, '2026-03-04 05:06'
    end

    # The current system log carries a message template and the values to
    # fill it with; the table shows the filled-in text.
    def test_system_log_entries_render_their_message_template
      entry = {
        'key'         => 'CLIENT_CONNECTED_WIRELESS_2',
        'title_raw'   => 'WiFi Client Connected',
        'message_raw' => '{CLIENT} connected to {WLAN} on {DEVICE}.',
        'parameters'  => { 'CLIENT' => { 'id' => 'aa:bb:cc:dd:ee:ff', 'name' => 'Thermostat' },
                           'WLAN'   => { 'id' => 'w1', 'name' => 'Home' },
                           'DEVICE' => { 'id' => '11:22:33:44:55:66', 'name' => 'AP-Garage' } },
        'severity'    => 'LOW',
        'subcategory' => 'MONITORING_WIFI',
        'timestamp'   => Time.new(2026, 3, 4, 5, 6, 0).to_i * 1000
      }
      out = render(:events, 'system-log' => [entry])

      assert_includes out, 'Thermostat connected to Home on AP-Garage.'
      assert_includes out, 'WiFi Client Connected'
      assert_includes out, 'MONITORING_WIFI'
      assert_includes out, '2026-03-04 05:06'
      assert_match(/\|\s+low\s+\|/, out)
    end

    def test_events_filter_by_type_matches_the_title_too
      routes = { 'system-log' => [
        { 'key' => 'ADMIN_ACCESS', 'title_raw' => 'Network Accessed', 'message_raw' => '{ADMIN} logged in' },
        { 'key' => 'CLIENT_ROAMED', 'title_raw' => 'Client Roamed', 'message_raw' => 'roamed' }
      ] }

      assert_includes render(:events, routes, type: 'accessed'), 'Network Accessed'
      refute_includes render(:events, routes, type: 'accessed'), 'Client Roamed'
    end

    def test_threat_severity_filter_understands_the_controller_s_levels
      routes = { 'system-log' => [
        { 'title_raw' => 'Severe', 'severity' => 'VERY_HIGH', 'message_raw' => 'x' },
        { 'title_raw' => 'Minor',  'severity' => 'INFO',      'message_raw' => 'y' }
      ] }
      out = render(:threats, routes, severity: 'high')

      assert_includes out, 'Severe'
      refute_includes out, 'Minor'
    end

    def test_alarms_report_an_empty_window_plainly
      out = render(:alarms, 'system-log' => [])

      assert_includes out, 'No alarms in the last 24h'
    end

    # --- vlans and vpn --------------------------------------------------------

    def test_vlans_exclude_wan_networks_by_default
      routes = { NETWORK_PATH => [
        { 'name' => 'LAN', 'vlan' => 1, 'purpose' => 'corporate' },
        { 'name' => 'WAN', 'purpose' => 'wan' }
      ] }

      assert_includes render(:vlans, routes), 'LAN'
      refute_includes render(:vlans, routes), 'WAN'
      assert_includes render(:vlans, routes, all: true), 'WAN'
    end

    def test_vpn_names_the_auth_method_without_printing_the_key
      out = render(:vpn, NETWORK_PATH => [
                     { 'name' => 'Road Warrior', 'purpose' => 'remote-user-vpn',
                       'vpn_type' => 'l2tp-server', 'x_ipsec_pre_shared_key' => 'supersecret' }
                   ])

      refute_includes out, 'supersecret'
      assert_includes out, 'pre-shared key'
    end

    def test_vpn_json_redacts_the_pre_shared_key
      out = render(:vpn, { NETWORK_PATH => [
                     { 'name' => 'v', 'purpose' => 'site-vpn', 'x_ipsec_pre_shared_key' => 'supersecret' }
                   ] }, json: true)

      refute_includes out, 'supersecret'
    end

    def test_non_vpn_networks_are_left_out
      out = render(:vpn, NETWORK_PATH => [{ 'name' => 'LAN', 'purpose' => 'corporate' }])

      assert_includes out, 'No VPN networks configured'
    end

    # --- firmware and ports ---------------------------------------------------

    def test_firmware_can_narrow_to_devices_with_an_update
      routes = { 'stat/device' => [
        { 'name' => 'Old', 'version' => '6.0.0', 'upgradable' => true, 'upgrade_to_firmware' => '6.5.0' },
        { 'name' => 'Current', 'version' => '6.5.0', 'upgradable' => false }
      ] }
      out = render(:firmware, routes, outdated: true)

      assert_includes out, 'Old'
      refute_includes out, 'Current'
    end

    def test_port_errors_hide_clean_ports_by_default
      routes = { 'stat/device' => [{ 'name' => 'Switch', 'port_table' => [
        { 'port_idx' => 1, 'rx_errors' => 0, 'tx_errors' => 0, 'up' => true, 'full_duplex' => true },
        { 'port_idx' => 2, 'rx_errors' => 42, 'up' => true, 'full_duplex' => true }
      ] }] }
      out = render(:port_errors, routes)

      assert_includes out, '42'
      refute_match(/\|\s+1\s+\|/, out)
    end

    def test_port_errors_can_show_every_port
      routes = { 'stat/device' => [{ 'name' => 'Switch', 'port_table' => [
        { 'port_idx' => 1, 'rx_errors' => 0, 'up' => true, 'full_duplex' => true }
      ] }] }

      assert_includes render(:port_errors, routes, all: true), 'Switch'
      assert_includes render(:port_errors, routes), 'No ports reporting errors'
    end

    # A live link that negotiated half duplex is nearly always a fault.
    def test_half_duplex_on_a_live_link_counts_as_a_fault
      routes = { 'stat/device' => [{ 'name' => 'Switch', 'port_table' => [
        { 'port_idx' => 3, 'up' => true, 'full_duplex' => false, 'speed' => 100 }
      ] }] }
      out = render(:port_errors, routes)

      assert_includes out, 'half'
    end

    # --- wifi experience ------------------------------------------------------

    def test_wifi_experience_computes_signal_to_noise_and_retry_rate
      routes = { 'stat/sta' => [{ 'name' => 'Laptop', 'is_wired' => false, 'signal' => -55,
                                  'noise' => -95, 'wifi_tx_attempts' => 1000, 'wifi_tx_retries' => 125 }] }
      out = render(:wifi_experience, routes)

      assert_includes out, '40 dB'
      assert_includes out, '12.5%'
    end

    def test_wifi_experience_can_narrow_to_weak_clients
      routes = { 'stat/sta' => [
        { 'name' => 'Close', 'is_wired' => false, 'signal' => -45 },
        { 'name' => 'Distant', 'is_wired' => false, 'signal' => -85 }
      ] }
      out = render(:wifi_experience, routes, signal_below: -70)

      assert_includes out, 'Distant'
      refute_includes out, 'Close'
    end

    def test_wired_clients_are_left_out_of_the_wireless_view
      routes = { 'stat/sta' => [{ 'name' => 'Server', 'is_wired' => true }] }

      assert_includes render(:wifi_experience, routes), 'No wireless clients connected'
    end

    # --- clients filters ------------------------------------------------------

    def test_clients_can_narrow_to_ones_nobody_has_named
      routes = { 'stat/sta' => [
        { 'name' => 'Laptop', 'mac' => 'aa:bb:cc:dd:ee:01' },
        { 'hostname' => 'unknown-device', 'mac' => 'aa:bb:cc:dd:ee:02' }
      ] }
      out = render(:clients, routes, unknown: true)

      assert_includes out, 'unknown-device'
      refute_includes out, 'Laptop'
    end

    def test_clients_can_narrow_to_guests
      routes = { 'stat/sta' => [
        { 'name' => 'Guest', 'is_guest' => true, 'mac' => 'aa:bb:cc:dd:ee:01' },
        { 'name' => 'Trusted', 'mac' => 'aa:bb:cc:dd:ee:02' }
      ] }
      out = render(:clients, routes, guest: true)

      assert_includes out, 'Guest'
      refute_includes out, 'Trusted'
    end

    def test_clients_can_narrow_to_recent_arrivals
      routes = { 'stat/sta' => [
        { 'name' => 'New', 'first_seen' => Time.now.to_i - 3600, 'mac' => 'aa:bb:cc:dd:ee:01' },
        { 'name' => 'Established', 'first_seen' => Time.now.to_i - (30 * 86_400), 'mac' => 'aa:bb:cc:dd:ee:02' }
      ] }
      out = render(:clients, routes, since: 24)

      assert_includes out, 'New'
      refute_includes out, 'Established'
    end

    def test_clients_can_narrow_to_a_vlan
      routes = {
        'stat/sta'   => [{ 'name' => 'IoTBulb', 'network_id' => 'n2', 'mac' => 'aa:bb:cc:dd:ee:01' },
                         { 'name' => 'Desktop', 'network_id' => 'n1', 'mac' => 'aa:bb:cc:dd:ee:02' }],
        NETWORK_PATH => [{ '_id' => 'n1', 'vlan' => 1 }, { '_id' => 'n2', 'vlan' => 30 }]
      }
      out = render(:clients, routes, vlan: 30)

      assert_includes out, 'IoTBulb'
      refute_includes out, 'Desktop'
    end

    # Untagged networks report no vlan at all, so they answer to 0.
    def test_untagged_networks_answer_to_vlan_zero
      routes = {
        'stat/sta'   => [{ 'name' => 'Untagged', 'network_id' => 'n1', 'mac' => 'aa:bb:cc:dd:ee:01' }],
        NETWORK_PATH => [{ '_id' => 'n1', 'name' => 'Default' }]
      }

      assert_includes render(:clients, routes, vlan: 0), 'Untagged'
    end
  end
end
