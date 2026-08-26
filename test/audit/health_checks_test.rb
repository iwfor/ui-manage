require_relative '../test_helper'

module UiManage
  module Audit
    class HealthChecksTest < TestCase
      def device(**overrides)
        { 'name' => 'UDM', 'type' => 'udm', 'state' => 1, 'uptime' => 900_000 }.merge(overrides)
      end

      def port(**overrides)
        { 'port_idx' => 1, 'up' => true, 'full_duplex' => true,
          'rx_packets' => 1_000_000, 'tx_packets' => 1_000_000 }.merge(overrides)
      end

      # --- firmware ----------------------------------------------------------

      def test_an_upgradable_device_is_reported
        report = audit_report(:firmware_update_available,
                              { 'stat/device' => [device('version' => '6.0.0', 'upgradable' => true,
                                                         'upgrade_to_firmware' => '6.5.0')] })

        assert_equal :medium, report.worst_severity
        assert_includes report.findings.first.message, '6.5.0'
      end

      def test_a_current_device_passes
        report = audit_report(:firmware_update_available,
                              { 'stat/device' => [device('upgradable' => false)] })

        assert report.clean?
      end

      # --- memory ------------------------------------------------------------

      def test_memory_from_a_ready_made_percentage
        report = audit_report(:device_memory,
                              { 'stat/device' => [device('system-stats' => { 'mem' => '92' })] })

        assert_equal :high, report.worst_severity
        assert_includes report.findings.first.message, '92.0%'
      end

      # Older devices report raw totals rather than a percentage.
      def test_memory_computed_from_raw_totals
        report = audit_report(:device_memory,
                              { 'stat/device' => [device('sys_stats' => { 'mem_total' => 1000,
                                                                          'mem_used' => 950 })] })

        refute report.clean?
        assert_equal 95.0, report.findings.first.evidence['memory_percent']
      end

      def test_a_device_reporting_no_memory_figures_is_not_reported
        assert audit_report(:device_memory, { 'stat/device' => [device] }).clean?
      end

      def test_memory_below_the_threshold_passes
        report = audit_report(:device_memory,
                              { 'stat/device' => [device('system-stats' => { 'mem' => '40' })] })

        assert report.clean?
      end

      # --- temperature -------------------------------------------------------

      def test_a_hot_device_is_reported_with_its_sensor
        report = audit_report(:device_temperature,
                              { 'stat/device' => [device('temperatures' => [
                                { 'name' => 'CPU', 'value' => 95 }, { 'name' => 'PHY', 'value' => 60 }
                              ])] })

        assert_includes report.findings.first.message, '95.0°C'
        assert_equal 'CPU', report.findings.first.evidence['sensor']
      end

      def test_a_single_temperature_field_is_understood
        report = audit_report(:device_temperature,
                              { 'stat/device' => [device('general_temperature' => 90)] })

        refute report.clean?
      end

      # Most UniFi hardware reports no temperature. Passing would claim
      # everything is cool; nothing was measured.
      def test_a_fleet_reporting_no_temperature_skips_rather_than_passing
        report = audit_report(:device_temperature, { 'stat/device' => [device] })

        assert_equal 1, report.skipped.size
        assert_empty report.passed
      end

      # --- storage -----------------------------------------------------------

      def test_full_storage_is_reported
        report = audit_report(:device_storage,
                              { 'stat/device' => [device('storage' => [
                                { 'name' => 'sda', 'size' => 1000, 'used' => 950, 'mount_point' => '/' }
                              ])] })

        assert_equal :high, report.worst_severity
        assert_includes report.findings.first.message, '95.0%'
      end

      def test_a_device_without_storage_information_skips
        report = audit_report(:device_storage, { 'stat/device' => [device] })

        assert_equal 1, report.skipped.size
      end

      # --- uptime ------------------------------------------------------------

      def test_a_recently_restarted_device_is_reported
        report = audit_report(:device_recent_reboot, { 'stat/device' => [device('uptime' => 600)] })

        assert_equal :medium, report.worst_severity
        assert_includes report.findings.first.message, '10 minutes'
      end

      def test_a_long_running_device_passes
        assert audit_report(:device_recent_reboot, { 'stat/device' => [device] }).clean?
      end

      # --- WAN ---------------------------------------------------------------

      def test_a_down_uplink_is_critical
        report = audit_report(:wan_status,
                              { 'stat/device' => [device('wan1' => { 'name' => 'Fibre', 'up' => false })] })

        assert_equal :critical, report.worst_severity
        assert_includes report.findings.first.message, 'Fibre is down'
      end

      def test_a_disabled_uplink_is_not_reported
        report = audit_report(:wan_status,
                              { 'stat/device' => [device('wan1' => { 'up' => false, 'enable' => false })] })

        assert report.clean?
      end

      # Failover working is fine; failover working unnoticed is not.
      def test_running_on_the_secondary_while_the_primary_is_up_is_reported
        report = audit_report(:wan_status,
                              { 'stat/device' => [device(
                                'wan1' => { 'name' => 'Fibre', 'up' => true, 'is_uplink' => false },
                                'wan2' => { 'name' => 'LTE', 'up' => true, 'is_uplink' => true }
                              )] })

        assert_equal :high, report.worst_severity
        assert_includes report.findings.first.message, 'secondary uplink'
      end

      def test_a_device_with_no_wan_information_skips
        report = audit_report(:wan_status, { 'stat/device' => [device] })

        assert_equal 1, report.skipped.size
      end

      def test_high_latency_is_reported
        report = audit_report(:wan_latency,
                              { 'stat/health' => [{ 'subsystem' => 'wan', 'latency' => 250 }] })

        assert_includes report.findings.first.message, '250ms'
      end

      def test_normal_latency_passes
        report = audit_report(:wan_latency,
                              { 'stat/health' => [{ 'subsystem' => 'wan', 'latency' => 12 }] })

        assert report.clean?
      end

      # Absence of a loss figure is not zero loss.
      def test_a_missing_loss_figure_is_not_reported_as_healthy
        report = audit_report(:wan_latency, { 'stat/health' => [{ 'subsystem' => 'wan' }] })

        assert report.clean?
        assert_empty report.findings
      end

      def test_no_wan_subsystem_skips
        report = audit_report(:wan_latency, { 'stat/health' => [{ 'subsystem' => 'lan' }] })

        assert_equal 1, report.skipped.size
      end

      # --- ports -------------------------------------------------------------

      # Counters are cumulative since boot, so the check judges a rate.
      def test_a_few_errors_on_a_long_running_port_are_not_reported
        report = audit_report(:port_errors,
                              { 'stat/device' => [device('port_table' => [port('rx_errors' => 5)])] })

        assert report.clean?
      end

      def test_a_high_error_rate_is_reported
        report = audit_report(:port_errors,
                              { 'stat/device' => [device('port_table' => [
                                port('rx_packets' => 1000, 'tx_packets' => 0, 'rx_errors' => 50)
                              ])] })

        refute report.clean?
        assert_equal 5.0, report.findings.first.evidence['error_rate_percent']
      end

      def test_the_error_rate_threshold_is_configurable
        routes   = { 'stat/device' => [device('port_table' => [
          port('rx_packets' => 1000, 'tx_packets' => 0, 'rx_errors' => 1)
        ])] }
        settings = Settings.new(path: nil, thresholds: { 'port_error_rate_percent' => 0.05 })

        assert audit_report(:port_errors, routes).clean?
        refute audit_report(:port_errors, routes, settings: settings).clean?
      end

      def test_a_half_duplex_link_is_reported
        report = audit_report(:port_duplex,
                              { 'stat/device' => [device('port_table' => [
                                port('full_duplex' => false, 'speed' => 100)
                              ])] })

        assert_equal :medium, report.worst_severity
        assert_includes report.findings.first.message, 'half duplex'
      end

      def test_a_down_port_at_half_duplex_is_not_reported
        report = audit_report(:port_duplex,
                              { 'stat/device' => [device('port_table' => [
                                port('up' => false, 'full_duplex' => false)
                              ])] })

        assert report.clean?
      end

      # --- PoE ---------------------------------------------------------------

      def test_poe_draw_near_the_budget_is_reported
        report = audit_report(:poe_budget,
                              { 'stat/device' => [device('total_max_power' => 100, 'port_table' => [
                                port('poe_power' => '50'), port('port_idx' => 2, 'poe_power' => '45')
                              ])] })

        assert_equal :high, report.worst_severity
        assert_equal 95.0, report.findings.first.evidence['percent']
      end

      def test_moderate_poe_draw_passes
        report = audit_report(:poe_budget,
                              { 'stat/device' => [device('total_max_power' => 100,
                                                         'port_table' => [port('poe_power' => '20')])] })

        assert report.clean?
      end

      def test_a_fleet_reporting_no_poe_budget_skips
        report = audit_report(:poe_budget, { 'stat/device' => [device] })

        assert_equal 1, report.skipped.size
      end

      # --- addressing --------------------------------------------------------

      def test_a_nearly_full_dhcp_pool_is_reported
        clients = (1..95).map { |i| { 'ip' => "10.0.0.#{i + 10}" } }
        report  = audit_report(:dhcp_pool_exhaustion,
                               'networkconf' => [{ 'name' => 'LAN', 'dhcpd_enabled' => true,
                                                   'dhcpd_start' => '10.0.0.11', 'dhcpd_stop' => '10.0.0.110' }],
                               'stat/sta'    => clients)

        assert_equal :high, report.worst_severity
        assert_equal 95, report.findings.first.evidence['in_use']
      end

      def test_clients_outside_the_pool_do_not_count_towards_it
        clients = (1..95).map { |i| { 'ip' => "192.168.9.#{i}" } }
        report  = audit_report(:dhcp_pool_exhaustion,
                               'networkconf' => [{ 'name' => 'LAN', 'dhcpd_enabled' => true,
                                                   'dhcpd_start' => '10.0.0.11', 'dhcpd_stop' => '10.0.0.110' }],
                               'stat/sta'    => clients)

        assert report.clean?
      end

      def test_overlapping_subnets_are_reported
        report = audit_report(:subnet_overlap,
                              { 'networkconf' => [
                                { 'name' => 'LAN', 'ip_subnet' => '10.0.0.0/16' },
                                { 'name' => 'IoT', 'ip_subnet' => '10.0.5.0/24' }
                              ] })

        assert_equal :high, report.worst_severity
        assert_includes report.findings.first.message, 'overlaps'
      end

      def test_distinct_subnets_pass
        report = audit_report(:subnet_overlap,
                              { 'networkconf' => [
                                { 'name' => 'LAN', 'ip_subnet' => '10.0.1.0/24' },
                                { 'name' => 'IoT', 'ip_subnet' => '10.0.2.0/24' }
                              ] })

        assert report.clean?
      end

      def test_an_unparseable_subnet_is_skipped_over_rather_than_crashing
        report = audit_report(:subnet_overlap,
                              { 'networkconf' => [
                                { 'name' => 'Broken', 'ip_subnet' => 'not-an-address' },
                                { 'name' => 'LAN', 'ip_subnet' => '10.0.1.0/24' }
                              ] })

        assert report.clean?
        assert_empty report.errored
      end

      def test_duplicate_reservations_are_reported
        report = audit_report(:dhcp_reservation,
                              'rest/user'   => [
                                { 'name' => 'A', 'mac' => 'aa', 'use_fixedip' => true, 'fixed_ip' => '10.0.0.5' },
                                { 'name' => 'B', 'mac' => 'bb', 'use_fixedip' => true, 'fixed_ip' => '10.0.0.5' }
                              ],
                              'networkconf' => [])

        refute report.clean?
        assert_includes report.findings.first.message, '2 clients reserve 10.0.0.5'
      end

      def test_a_reservation_outside_its_network_is_reported
        report = audit_report(:dhcp_reservation,
                              'rest/user'   => [{ 'name' => 'Printer', 'mac' => 'aa', 'use_fixedip' => true,
                                                  'fixed_ip' => '192.168.50.5', 'network_id' => 'n1' }],
                              'networkconf' => [{ '_id' => 'n1', 'name' => 'LAN', 'ip_subnet' => '10.0.0.0/24' }])

        refute report.clean?
        assert_includes report.findings.first.message, 'outside LAN'
      end

      def test_valid_reservations_pass
        report = audit_report(:dhcp_reservation,
                              'rest/user'   => [{ 'name' => 'Printer', 'mac' => 'aa', 'use_fixedip' => true,
                                                  'fixed_ip' => '10.0.0.5', 'network_id' => 'n1' }],
                              'networkconf' => [{ '_id' => 'n1', 'name' => 'LAN', 'ip_subnet' => '10.0.0.0/24' }])

        assert report.clean?
      end

      # --- wireless ----------------------------------------------------------

      def test_weak_clients_are_grouped_into_one_finding
        clients = 3.times.map { |i| { 'mac' => "aa:0#{i}", 'name' => "C#{i}", 'signal' => -85 } }
        report  = audit_report(:wifi_client_quality, { 'stat/sta' => clients })

        assert_equal 1, report.findings.size
        assert_equal 'signal', report.findings.first.subject
        assert_equal 3, report.findings.first.evidence['count']
      end

      def test_signal_and_retries_are_reported_separately
        clients = [
          { 'mac' => 'a', 'signal' => -85 },
          { 'mac' => 'b', 'signal' => -50, 'wifi_tx_attempts' => 1000, 'wifi_tx_retries' => 400 }
        ]
        report = audit_report(:wifi_client_quality, { 'stat/sta' => clients })

        assert_equal %w[retries signal], report.findings.map(&:subject).sort
      end

      def test_healthy_wireless_clients_pass
        report = audit_report(:wifi_client_quality, { 'stat/sta' => [{ 'mac' => 'a', 'signal' => -50 }] })

        assert report.clean?
      end

      def test_wired_clients_are_not_judged_on_signal
        report = audit_report(:wifi_client_quality,
                              { 'stat/sta' => [{ 'mac' => 'a', 'is_wired' => true, 'signal' => -90 }] })

        assert report.clean?
      end

      def test_two_access_points_on_the_same_channel_are_reported
        report = audit_report(:radio_channel_overlap,
                              { 'stat/device' => [
                                device('name' => 'AP1', 'radio_table_stats' => [{ 'radio' => 'ng', 'channel' => 6 }]),
                                device('name' => 'AP2', 'radio_table_stats' => [{ 'radio' => 'ng', 'channel' => 6 }])
                              ] })

        assert_equal :medium, report.worst_severity
        assert_includes report.findings.first.message, 'same channel'
      end

      # 2.4 GHz channels are 20 MHz wide but 5 MHz apart, so neighbours
      # interfere even on different numbers.
      def test_adjacent_channels_overlap_on_two_point_four_gigahertz
        report = audit_report(:radio_channel_overlap,
                              { 'stat/device' => [
                                device('name' => 'AP1', 'radio_table_stats' => [{ 'radio' => 'ng', 'channel' => 6 }]),
                                device('name' => 'AP2', 'radio_table_stats' => [{ 'radio' => 'ng', 'channel' => 8 }])
                              ] })

        assert_equal :low, report.worst_severity
      end

      def test_the_non_overlapping_two_point_four_channels_pass
        report = audit_report(:radio_channel_overlap,
                              { 'stat/device' => [
                                device('name' => 'AP1', 'radio_table_stats' => [{ 'radio' => 'ng', 'channel' => 1 }]),
                                device('name' => 'AP2', 'radio_table_stats' => [{ 'radio' => 'ng', 'channel' => 6 }])
                              ] })

        assert report.clean?
      end

      # 5 GHz channels do not overlap between different numbers.
      def test_different_five_gigahertz_channels_do_not_overlap
        report = audit_report(:radio_channel_overlap,
                              { 'stat/device' => [
                                device('name' => 'AP1', 'radio_table_stats' => [{ 'radio' => 'na', 'channel' => 36 }]),
                                device('name' => 'AP2', 'radio_table_stats' => [{ 'radio' => 'na', 'channel' => 40 }])
                              ] })

        assert report.clean?
      end

      def test_a_busy_channel_is_reported
        report = audit_report(:radio_utilization,
                              { 'stat/device' => [device('name' => 'AP1', 'radio_table_stats' => [
                                { 'radio' => 'ng', 'channel' => 6, 'cu_total' => 88 }
                              ])] })

        assert_equal :medium, report.worst_severity
        assert_includes report.findings.first.message, '88%'
      end

      def test_radios_reporting_no_utilization_skip
        report = audit_report(:radio_utilization,
                              { 'stat/device' => [device('radio_table_stats' => [{ 'radio' => 'ng' }])] })

        assert_equal 1, report.skipped.size
      end
    end
  end
end
