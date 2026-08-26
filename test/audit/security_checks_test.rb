require_relative '../test_helper'

module UiManage
  module Audit
    class SecurityChecksTest < TestCase
      def settings_section(key, fields = {}) = [{ 'key' => key }.merge(fields)]

      def wlan(**overrides)
        { 'name' => 'Home', 'enabled' => true, 'security' => 'wpapsk', 'wpa_mode' => 'wpa2',
          'wpa_enc' => 'ccmp', 'pmf_mode' => 'required',
          'x_passphrase' => 'a-long-enough-passphrase' }.merge(overrides)
      end

      def forward(**overrides)
        { 'name' => 'Web', 'enabled' => true, 'src' => '203.0.113.5',
          'dst_port' => '8080', 'fwd' => '10.0.0.5', 'fwd_port' => '8080' }.merge(overrides)
      end

      def rule(**overrides)
        { 'name' => 'Rule', 'enabled' => true, 'action' => 'drop', 'ruleset' => 'LAN_IN',
          'logging' => true }.merge(overrides)
      end

      # --- wlan_pmf ----------------------------------------------------------

      def test_pmf_disabled_is_reported
        report = audit_report(:wlan_pmf, { 'wlanconf' => [wlan('pmf_mode' => 'disabled')] })

        assert_equal :medium, report.worst_severity
        assert_includes report.findings.first.message, 'deauthentication'
      end

      def test_pmf_optional_or_required_passes
        %w[optional required].each do |mode|
          assert audit_report(:wlan_pmf, { 'wlanconf' => [wlan('pmf_mode' => mode)] }).clean?
        end
      end

      # An open network has no management frame protection to turn on, and is
      # already reported by wlan_encryption.
      def test_an_open_network_is_not_also_reported_for_pmf
        report = audit_report(:wlan_pmf,
                              { 'wlanconf' => [wlan('security' => 'open', 'pmf_mode' => 'disabled')] })

        assert report.clean?
      end

      # --- wlan_guest_network ------------------------------------------------

      def test_a_guest_ssid_on_a_corporate_network_is_reported
        report = audit_report(:wlan_guest_network,
                              'wlanconf'    => [wlan('is_guest' => true, 'networkconf_id' => 'n1')],
                              'networkconf' => [{ '_id' => 'n1', 'name' => 'LAN', 'purpose' => 'corporate' }])

        assert_equal :high, report.worst_severity
        assert_includes report.findings.first.message, 'not isolated'
      end

      def test_a_guest_ssid_on_a_guest_network_passes
        report = audit_report(:wlan_guest_network,
                              'wlanconf'    => [wlan('is_guest' => true, 'networkconf_id' => 'n1')],
                              'networkconf' => [{ '_id' => 'n1', 'name' => 'Guest', 'purpose' => 'guest' }])

        assert report.clean?
      end

      def test_a_non_guest_ssid_is_not_judged
        report = audit_report(:wlan_guest_network,
                              'wlanconf'    => [wlan('networkconf_id' => 'n1')],
                              'networkconf' => [{ '_id' => 'n1', 'name' => 'LAN', 'purpose' => 'corporate' }])

        assert report.clean?
      end

      # --- rogue_ap_impersonation --------------------------------------------

      def test_a_neighbour_broadcasting_our_ssid_is_critical
        report = audit_report(:rogue_ap_impersonation,
                              'rogueap'  => [{ 'essid' => 'Home', 'bssid' => 'aa:bb:cc:00:00:01', 'signal' => -40 }],
                              'wlanconf' => [wlan('name' => 'Home')])

        assert_equal :critical, report.worst_severity
        assert_includes report.findings.first.message, '-40 dBm'
      end

      def test_an_unrelated_neighbour_passes
        report = audit_report(:rogue_ap_impersonation,
                              'rogueap'  => [{ 'essid' => 'Cafe', 'bssid' => 'aa:bb:cc:00:00:01' }],
                              'wlanconf' => [wlan('name' => 'Home')])

        assert report.clean?
      end

      # A hidden neighbour reports a blank ESSID; that is not a match for
      # every SSID we run.
      def test_a_hidden_neighbour_is_not_treated_as_a_match
        report = audit_report(:rogue_ap_impersonation,
                              'rogueap'  => [{ 'essid' => '', 'bssid' => 'aa:bb:cc:00:00:01' }],
                              'wlanconf' => [wlan('name' => 'Home')])

        assert report.clean?
      end

      def test_the_check_skips_when_the_wlan_list_cannot_be_read
        report = audit_report(:rogue_ap_impersonation,
                              'rogueap'  => [{ 'essid' => 'Home', 'bssid' => 'aa:bb:cc:00:00:01' }],
                              'wlanconf' => 403)

        assert_equal 1, report.skipped.size
        assert_empty report.passed
      end

      # --- port_forward_sensitive --------------------------------------------

      def test_a_forward_exposing_ssh_is_critical
        report = audit_report(:port_forward_sensitive,
                              { 'portforward' => [forward('name' => 'SSH', 'dst_port' => '22', 'fwd_port' => '22')] })

        assert_equal :critical, report.worst_severity
        assert_includes report.findings.first.message, '22'
      end

      def test_a_port_range_covering_a_sensitive_port_is_caught
        report = audit_report(:port_forward_sensitive,
                              { 'portforward' => [forward('dst_port' => '20-30', 'fwd_port' => '20-30')] })

        refute report.clean?
        assert_includes report.findings.first.evidence['ports'], 22
      end

      def test_an_ordinary_forward_passes
        assert audit_report(:port_forward_sensitive, { 'portforward' => [forward] }).clean?
      end

      def test_a_disabled_forward_is_not_reported
        report = audit_report(:port_forward_sensitive,
                              { 'portforward' => [forward('dst_port' => '22', 'enabled' => false)] })

        assert report.clean?
      end

      def test_which_ports_count_as_sensitive_is_configurable
        routes   = { 'portforward' => [forward('dst_port' => '8080', 'fwd_port' => '8080')] }
        settings = Settings.new(path: nil, thresholds: { 'sensitive_ports' => [8080] })

        assert audit_report(:port_forward_sensitive, routes).clean?
        refute audit_report(:port_forward_sensitive, routes, settings: settings).clean?
      end

      # --- port_forward_open_source ------------------------------------------

      def test_a_forward_from_any_source_is_reported
        ['', 'any', '0.0.0.0/0'].each do |src|
          report = audit_report(:port_forward_open_source, { 'portforward' => [forward('src' => src)] })

          refute report.clean?, "#{src.inspect} should count as any source"
        end
      end

      def test_a_forward_with_a_named_source_passes
        assert audit_report(:port_forward_open_source, { 'portforward' => [forward] }).clean?
      end

      # --- upnp / ssh / snmp / ips / auto-update ------------------------------

      def test_upnp_enabled_is_reported
        report = audit_report(:upnp_enabled, { 'get/setting' => settings_section('usg', 'upnp_enabled' => true) })

        assert_equal :high, report.worst_severity
      end

      def test_upnp_disabled_passes
        report = audit_report(:upnp_enabled, { 'get/setting' => settings_section('usg', 'upnp_enabled' => false) })

        assert report.clean?
      end

      # The failure this guards against: a field the controller never sent
      # reads as nil, and nil looks like "disabled".
      def test_a_setting_the_controller_does_not_report_skips_rather_than_passing
        report = audit_report(:upnp_enabled, { 'get/setting' => settings_section('usg') })

        assert_equal 1, report.skipped.size
        assert_empty report.passed
        assert_includes report.skipped.first.reason, 'upnp_enabled'
      end

      def test_a_missing_settings_section_skips_rather_than_passing
        report = audit_report(:upnp_enabled, { 'get/setting' => settings_section('mgmt') })

        assert_equal 1, report.skipped.size
        assert_includes report.skipped.first.reason, "'usg'"
      end

      def test_ssh_with_a_shared_password_outranks_ssh_with_keys
        with_password = audit_report(:device_ssh,
                                     { 'get/setting' => settings_section('mgmt', 'x_ssh_enabled' => true) })
        with_keys     = audit_report(:device_ssh,
                                     { 'get/setting' => settings_section('mgmt', 'x_ssh_enabled' => true,
                                                                                 'x_ssh_keys' => [{ 'name' => 'k' }]) })

        assert_equal :high,   with_password.worst_severity
        assert_equal :medium, with_keys.worst_severity
      end

      def test_ssh_disabled_passes
        report = audit_report(:device_ssh, { 'get/setting' => settings_section('mgmt', 'x_ssh_enabled' => false) })

        assert report.clean?
      end

      def test_snmp_v1_is_reported_and_a_default_community_adds_a_finding
        report = audit_report(:snmp_insecure,
                              { 'get/setting' => settings_section('snmp', 'enabled' => true,
                                                                          'community' => 'public') })

        assert_equal 2, report.findings.size
        assert report.findings.any? { |f| f.subject == 'community string' }
      end

      # The community string is a credential; the finding names the fact, not
      # the value.
      def test_the_snmp_community_string_is_never_printed
        report = audit_report(:snmp_insecure,
                              { 'get/setting' => settings_section('snmp', 'enabled' => true,
                                                                          'community' => 'sup3rs3cret') })

        report.findings.each do |finding|
          refute_includes finding.message, 'sup3rs3cret'
          refute_includes finding.evidence.to_s, 'sup3rs3cret'
        end
      end

      def test_ips_disabled_outranks_ips_in_detect_only_mode
        off    = audit_report(:ips_disabled, { 'get/setting' => settings_section('ips', 'ips_mode' => 'disabled') })
        detect = audit_report(:ips_disabled, { 'get/setting' => settings_section('ips', 'ips_mode' => 'detect') })
        block  = audit_report(:ips_disabled, { 'get/setting' => settings_section('ips', 'ips_mode' => 'detect_and_block') })

        assert_equal :high,   off.worst_severity
        assert_equal :medium, detect.worst_severity
        assert block.clean?
      end

      def test_an_unrecognised_ips_mode_skips_rather_than_guessing
        report = audit_report(:ips_disabled, { 'get/setting' => settings_section('ips', 'ips_mode' => 'somethingnew') })

        assert_equal 1, report.skipped.size
      end

      def test_auto_updates_disabled_is_reported
        report = audit_report(:auto_firmware_updates,
                              { 'get/setting' => settings_section('auto_upgrade', 'enabled' => false) })

        assert_equal :medium, report.worst_severity
      end

      # --- firewall ----------------------------------------------------------

      def test_an_any_any_accept_from_the_wan_is_critical
        report = audit_report(:firewall_permissive_rule,
                              { 'firewallrule' => [rule('action' => 'accept', 'ruleset' => 'WAN_IN')] })

        assert_equal :critical, report.worst_severity
      end

      def test_an_any_any_accept_between_internal_networks_is_high
        report = audit_report(:firewall_permissive_rule,
                              { 'firewallrule' => [rule('action' => 'accept', 'ruleset' => 'LAN_IN')] })

        assert_equal :high, report.worst_severity
      end

      def test_a_rule_restricted_by_address_or_group_passes
        by_address = audit_report(:firewall_permissive_rule,
                                  { 'firewallrule' => [rule('action' => 'accept', 'src_address' => '10.0.0.0/8')] })
        by_group   = audit_report(:firewall_permissive_rule,
                                  { 'firewallrule' => [rule('action' => 'accept',
                                                            'src_firewallgroup_ids' => ['g1'])] })

        assert by_address.clean?
        assert by_group.clean?
      end

      def test_a_drop_rule_is_not_a_permissive_rule
        assert audit_report(:firewall_permissive_rule, { 'firewallrule' => [rule] }).clean?
      end

      # One finding for the whole set rather than one per rule, which would
      # bury everything else on a site that never turned logging on.
      def test_unlogged_blocking_rules_produce_a_single_finding
        rules  = 5.times.map { |i| rule('name' => "Block #{i}", 'logging' => false) }
        report = audit_report(:firewall_rule_logging, { 'firewallrule' => rules })

        assert_equal 1, report.findings.size
        assert_equal 5, report.findings.first.evidence['count']
      end

      def test_logged_blocking_rules_pass
        assert audit_report(:firewall_rule_logging, { 'firewallrule' => [rule] }).clean?
      end

      def test_an_unreferenced_firewall_group_is_reported
        report = audit_report(:firewall_unused_group,
                              'firewallgroup' => [{ '_id' => 'g1', 'name' => 'Orphan', 'group_members' => [] }],
                              'firewallrule'  => [rule])

        assert_equal :info, report.worst_severity
        assert_equal 'Orphan', report.findings.first.subject
      end

      def test_a_referenced_firewall_group_passes
        report = audit_report(:firewall_unused_group,
                              'firewallgroup' => [{ '_id' => 'g1', 'name' => 'Used' }],
                              'firewallrule'  => [rule('dst_firewallgroup_ids' => ['g1'])])

        assert report.clean?
      end

      # --- admins ------------------------------------------------------------

      def test_an_admin_without_two_factor_is_reported
        report = audit_report(:admin_two_factor,
                              { 'sitemgr' => [{ 'name' => 'alice', 'x_has_totp' => false }] })

        assert_equal :high, report.worst_severity
      end

      def test_a_super_admin_without_two_factor_is_critical
        report = audit_report(:admin_two_factor,
                              { 'sitemgr' => [{ 'name' => 'root', 'is_super' => true, 'x_has_totp' => false }] })

        assert_equal :critical, report.worst_severity
      end

      def test_admins_with_two_factor_pass
        report = audit_report(:admin_two_factor,
                              { 'sitemgr' => [{ 'name' => 'alice', 'x_has_totp' => true }] })

        assert report.clean?
      end

      # Judging a controller that reports nothing as "nobody has 2FA" would be
      # a fabricated finding.
      def test_a_controller_reporting_no_two_factor_state_skips_the_check
        report = audit_report(:admin_two_factor, { 'sitemgr' => [{ 'name' => 'alice', 'role' => 'admin' }] })

        assert_equal 1, report.skipped.size
        assert_empty report.passed
      end

      # But when it reports for some and not others, the gap is stated rather
      # than assumed either way.
      def test_a_partially_reported_admin_list_reports_the_gap_at_info
        report = audit_report(:admin_two_factor,
                              { 'sitemgr' => [{ 'name' => 'alice', 'x_has_totp' => true },
                                              { 'name' => 'bob' }] })

        assert_equal 1, report.findings.size
        assert_equal :info, report.findings.first.severity
        assert_equal 'bob', report.findings.first.subject
      end

      def test_too_many_super_admins_is_reported
        admins = 4.times.map { |i| { 'name' => "admin#{i}", 'is_super' => true } }
        report = audit_report(:admin_super_count, { 'sitemgr' => admins })

        assert_equal :medium, report.worst_severity
        assert_equal 4, report.findings.first.evidence['count']
      end

      def test_the_super_admin_limit_is_configurable
        admins   = 3.times.map { |i| { 'name' => "admin#{i}", 'is_super' => true } }
        settings = Settings.new(path: nil, thresholds: { 'max_super_admins' => 5 })

        refute audit_report(:admin_super_count, { 'sitemgr' => admins }).clean?
        assert audit_report(:admin_super_count, { 'sitemgr' => admins }, settings: settings).clean?
      end

      # --- threat detections, devices, TLS -----------------------------------

      def test_recent_detections_are_grouped_by_signature
        events = [
          { 'inner_alert_signature' => 'ET SCAN', 'inner_alert_severity' => 1, 'src_ip' => '203.0.113.1' },
          { 'inner_alert_signature' => 'ET SCAN', 'inner_alert_severity' => 1, 'src_ip' => '203.0.113.2' },
          { 'inner_alert_signature' => 'ET INFO', 'inner_alert_severity' => 3, 'src_ip' => '203.0.113.3' }
        ]
        report = audit_report(:ips_recent_detections, { 'ips/event' => events })

        assert_equal 2, report.findings.size
        scan = report.findings.find { |f| f.subject == 'ET SCAN' }
        assert_equal 2, scan.evidence['count']
        assert_equal :high, scan.severity
      end

      def test_no_detections_passes
        assert audit_report(:ips_recent_detections, { 'ips/event' => [] }).clean?
      end

      def test_an_unadopted_device_is_reported
        report = audit_report(:device_unadopted,
                              { 'stat/device' => [{ 'model' => 'U6', 'mac' => 'aa:bb', 'state' => 2 }] })

        refute report.clean?
        assert_includes report.findings.first.message, 'pending adoption'
      end

      def test_a_failed_adoption_outranks_a_pending_one
        failed  = audit_report(:device_unadopted, { 'stat/device' => [{ 'mac' => 'a', 'state' => 9 }] })
        pending = audit_report(:device_unadopted, { 'stat/device' => [{ 'mac' => 'a', 'state' => 2 }] })

        assert_equal :high,   failed.worst_severity
        assert_equal :medium, pending.worst_severity
      end

      def test_an_adopted_device_passes
        assert audit_report(:device_unadopted, { 'stat/device' => [{ 'mac' => 'a', 'state' => 1 }] }).clean?
      end

      def test_an_unverified_controller_connection_is_reported
        refute audit_report(:controller_tls, {}, device: { 'verify_ssl' => false }).clean?
        assert audit_report(:controller_tls, {}, device: { 'verify_ssl' => true }).clean?
      end

      # A device saved before the setting existed also connects without
      # verification, so an absent value is not a pass.
      def test_a_device_with_no_tls_setting_recorded_is_reported
        refute audit_report(:controller_tls, {}, device: {}).clean?
      end
    end
  end
end
