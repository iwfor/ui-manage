require_relative '../test_helper'

module UiManage
  module Audit
    # The reference checks, exercised end to end through the runner — which
    # is also what proves the engine's own mechanics against real check code
    # rather than only against test doubles.
    class ChecksTest < TestCase
      def report_for(id, routes = {}, **options)
        routes, options = split_routes(routes, options)
        device   = options.fetch(:device, {})
        settings = options[:settings]
        client  = Client.new(host: 'unifi.test', api_key: 'k', transport: stub_transport(routes))
        context = Context.new(client: client, device: device,
                              settings: settings || Settings.new(path: nil))
        Runner.new(context: context, checks: [Registry.find(id)]).run
      end

      def wlan(**overrides)
        { 'name' => 'Home', 'enabled' => true, 'security' => 'wpapsk', 'wpa_mode' => 'wpa2',
          'wpa_enc' => 'ccmp', 'x_passphrase' => 'a-long-enough-passphrase' }.merge(overrides)
      end

      def settings_section(key, fields = {})
        [{ 'key' => key }.merge(fields)]
      end

      # --- wlan_encryption ---------------------------------------------------

      def test_an_open_ssid_is_critical
        report = report_for(:wlan_encryption, { 'wlanconf' => [wlan('security' => 'open')] })

        assert_equal :critical, report.worst_severity
        assert_includes report.findings.first.message, 'no encryption'
      end

      def test_wps_is_reported_below_an_unencrypted_network
        report = report_for(:wlan_encryption, { 'wlanconf' => [wlan('wps' => true)] })

        assert_equal :high, report.worst_severity
      end

      def test_one_ssid_can_produce_several_findings
        report = report_for(:wlan_encryption,
                            { 'wlanconf' => [wlan('wpa_mode' => 'wpa1', 'wpa_enc' => 'tkip', 'wps' => true)] })

        assert_equal 3, report.findings.size
        assert_equal ['Home'], report.findings.map(&:subject).uniq
      end

      def test_a_disabled_ssid_is_not_reported
        report = report_for(:wlan_encryption, { 'wlanconf' => [wlan('security' => 'open', 'enabled' => false)] })

        assert report.clean?
      end

      def test_a_properly_secured_ssid_passes
        report = report_for(:wlan_encryption, { 'wlanconf' => [wlan] })

        assert report.clean?
      end

      # --- wlan_passphrase ---------------------------------------------------

      def test_a_short_passphrase_is_reported_without_printing_it
        report  = report_for(:wlan_passphrase, { 'wlanconf' => [wlan('x_passphrase' => 'short12')] })
        finding = report.findings.first

        refute_includes finding.message, 'short12'
        refute_includes finding.evidence.to_s, 'short12'
        assert_includes finding.message, '7-character'
      end

      def test_the_passphrase_minimum_is_configurable
        routes   = { 'wlanconf' => [wlan('x_passphrase' => 'sixteencharacter')] }
        settings = Settings.new(path: nil, thresholds: { 'min_passphrase_chars' => 24 })

        assert report_for(:wlan_passphrase, routes).clean?
        refute report_for(:wlan_passphrase, routes, settings: settings).clean?
      end

      # An enterprise SSID has no passphrase; that is not a short one.
      def test_an_ssid_with_no_passphrase_is_not_reported_as_short
        report = report_for(:wlan_passphrase, { 'wlanconf' => [wlan('security' => 'wpaeap', 'x_passphrase' => '')] })

        assert report.clean?
      end

      # --- remote_access -----------------------------------------------------

      def test_remote_access_on_against_a_policy_of_off_is_a_finding
        report = report_for(:remote_access,
                            { 'get/setting' => settings_section('super_cloudaccess', 'enabled' => true) },
                            device: { 'remote_access_expected' => false })

        assert_equal :medium, report.worst_severity
        assert_includes report.findings.first.message, 'enabled'
      end

      def test_remote_access_off_against_a_policy_of_on_is_a_lesser_finding
        report = report_for(:remote_access,
                            { 'get/setting' => settings_section('super_cloudaccess', 'enabled' => false) },
                            device: { 'remote_access_expected' => true })

        assert_equal :low, report.worst_severity
      end

      def test_remote_access_matching_policy_passes
        report = report_for(:remote_access,
                            { 'get/setting' => settings_section('super_cloudaccess', 'enabled' => true) },
                            device: { 'remote_access_expected' => true })

        assert report.clean?
      end

      # With no policy recorded there is nothing to disagree with, so the
      # check states the setting rather than calling it wrong.
      def test_an_unset_policy_reports_the_setting_without_judging_it
        report = report_for(:remote_access,
                            { 'get/setting' => settings_section('super_cloudaccess', 'enabled' => true) })

        assert_equal :info, report.worst_severity
        assert_includes report.findings.first.message, 'ui-manage policy'
      end

      def test_a_controller_that_does_not_report_the_setting_skips_rather_than_passes
        report = report_for(:remote_access, { 'get/setting' => settings_section('mgmt') })

        assert_equal 1, report.skipped.size
        assert_empty report.passed
        assert_includes report.skipped.first.reason, 'super_cloudaccess'
      end

      def test_a_refused_settings_endpoint_skips_the_check
        report = report_for(:remote_access, { 'get/setting' => 403 })

        assert_equal 1, report.skipped.size
        assert_includes report.skipped.first.reason, 'not permitted'
      end

      # --- device_offline ----------------------------------------------------

      def test_a_disconnected_device_is_critical
        report = report_for(:device_offline,
                            { 'stat/device' => [{ 'name' => 'AP', 'state' => 0, 'model' => 'U6' }] })

        assert_equal :critical, report.worst_severity
        assert_includes report.findings.first.message, 'disconnected'
      end

      # A device mid-upgrade is briefly not connected by design.
      def test_a_device_mid_upgrade_is_not_reported
        report = report_for(:device_offline, { 'stat/device' => [{ 'name' => 'AP', 'state' => 4 }] })

        assert report.clean?
      end

      def test_connected_devices_pass
        report = report_for(:device_offline, { 'stat/device' => [{ 'name' => 'AP', 'state' => 1 }] })

        assert report.clean?
      end

      # --- device_cpu --------------------------------------------------------

      def test_cpu_above_the_threshold_is_reported
        report = report_for(:device_cpu,
                            { 'stat/device' => [{ 'name' => 'UDM', 'state' => 1,
                                                  'system-stats' => { 'cpu' => '93.5' } }] })

        assert_equal 1, report.findings.size
        assert_includes report.findings.first.message, '93.5%'
        assert_equal 80, report.findings.first.evidence['threshold']
      end

      def test_the_cpu_threshold_is_configurable
        routes   = { 'stat/device' => [{ 'name' => 'UDM', 'state' => 1, 'system-stats' => { 'cpu' => '50' } }] }
        settings = Settings.new(path: nil, thresholds: { 'cpu_percent' => 40 })

        assert report_for(:device_cpu, routes).clean?
        refute report_for(:device_cpu, routes, settings: settings).clean?
      end

      # A device that is not connected reports stale stats; judging them
      # would produce a finding about a number nobody can act on.
      def test_a_disconnected_device_is_not_judged_on_cpu
        report = report_for(:device_cpu,
                            { 'stat/device' => [{ 'name' => 'AP', 'state' => 0,
                                                  'system-stats' => { 'cpu' => '99' } }] })

        assert report.clean?
      end

      def test_a_device_reporting_no_cpu_figure_is_not_reported
        report = report_for(:device_cpu, { 'stat/device' => [{ 'name' => 'AP', 'state' => 1 }] })

        assert report.clean?
      end
    end

    class RegistryTest < TestCase
      def test_every_shipped_check_is_fully_declared
        Registry.all.each do |check|
          refute_nil check.id,       "#{check} has no id"
          refute_nil check.title,    "#{check.id} has no title"
          assert_includes %i[security health], check.category, "#{check.id} has an odd category"
          assert Severity.valid?(check.severity), "#{check.id} has an invalid severity"
          refute_nil check.remediation, "#{check.id} has no remediation text"
        end
      end

      def test_check_ids_are_unique
        ids = Registry.all.map(&:id)

        assert_equal ids.uniq, ids
      end

      def test_checks_can_be_narrowed_by_category
        assert Registry.select(category: :security).all? { |c| c.category == :security }
        refute_empty Registry.select(category: :health)
      end

      def test_checks_can_be_narrowed_by_glob
        selected = Registry.select(only: ['wlan_*'])

        refute_empty selected
        assert selected.all? { |c| c.id.to_s.start_with?('wlan_') }
      end

      def test_checks_can_be_excluded_by_glob
        refute Registry.select(skip: ['device_*']).any? { |c| c.id.to_s.start_with?('device_') }
      end

      def test_checks_can_be_narrowed_by_severity
        assert Registry.select(min_severity: :critical).all? { |c| c.severity == :critical }
      end

      def test_suppressed_checks_are_left_out_of_a_run
        settings = Settings.new(path: nil, suppressed_checks: ['wlan_encryption'])

        refute Registry.select(settings: settings).map(&:id).include?(:wlan_encryption)
      end

      def test_loading_twice_does_not_duplicate_checks
        before = Registry.all.size
        Registry.load!

        assert_equal before, Registry.all.size
      end
    end
  end
end
