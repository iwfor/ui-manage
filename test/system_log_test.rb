require_relative 'test_helper'

module UiManage
  # SystemLog reads both the current system-log entries and the legacy
  # /stat/event, /stat/alarm, and /stat/ips/event shapes, so a view or check
  # never has to know which controller version answered.
  class SystemLogTest < TestCase
    def v2(**fields)
      { 'message_raw' => '{CLIENT} joined {WLAN}',
        'parameters'  => { 'CLIENT' => { 'id' => 'aa:bb', 'name' => 'Phone' }, 'WLAN' => { 'id' => 'w1' } },
        'severity'    => 'HIGH', 'status' => 'NEW', 'timestamp' => 1_788_616_693_564 }.merge(fields)
    end

    # --- messages -------------------------------------------------------------

    def test_a_template_is_filled_from_its_parameters_preferring_names_over_ids
      assert_equal 'Phone joined w1', SystemLog.message(v2)
    end

    def test_a_placeholder_with_no_parameter_is_left_visible_rather_than_dropped
      assert_equal 'Phone joined {NOWHERE}', SystemLog.message(v2('message_raw' => '{CLIENT} joined {NOWHERE}'))
    end

    def test_a_list_parameter_names_each_member
      entry = v2('message_raw' => 'Duplicate IP on {CLIENTS}',
                 'parameters'  => { 'CLIENTS' => { 'clients' => [{ 'name' => 'TV' }, { 'name' => 'Printer' }] } })

      assert_equal 'Duplicate IP on TV, Printer', SystemLog.message(entry)
    end

    def test_a_legacy_entry_reads_its_msg_field
      assert_equal 'WAN down', SystemLog.message('msg' => 'WAN down')
      assert_equal '', SystemLog.message({})
    end

    # --- titles and categories ------------------------------------------------

    def test_the_title_is_the_v2_title_or_the_ips_signature_or_the_key
      assert_equal 'Network Accessed', SystemLog.title('title_raw' => 'Network Accessed', 'key' => 'K')
      assert_equal 'WAN1 Internet Down',
                   SystemLog.title(v2('title_raw' => '{WAN_ID} Internet Down',
                                      'parameters' => { 'WAN_ID' => { 'name' => 'WAN1' } }))
      assert_equal 'ET SCAN',          SystemLog.title('inner_alert_signature' => 'ET SCAN', 'key' => 'K')
      assert_equal 'K',                SystemLog.title('key' => 'K')
    end

    def test_the_category_prefers_the_most_specific_field_each_shape_offers
      assert_equal 'MONITORING_WIFI', SystemLog.category('category' => 'CLIENT_DEVICES', 'subcategory' => 'MONITORING_WIFI')
      assert_equal 'trojan',          SystemLog.category('subsystem' => 'wan', 'catname' => 'trojan')
      assert_equal 'wan',             SystemLog.category('subsystem' => 'wan')
    end

    # --- severity -------------------------------------------------------------

    def test_controller_severities_map_onto_low_medium_high
      { 'INFO' => 'low', 'LOW' => 'low', 'MEDIUM' => 'medium', 'WARNING' => 'medium',
        'HIGH' => 'high', 'VERY_HIGH' => 'high' }.each do |raw, expected|
        assert_equal expected, SystemLog.severity('severity' => raw), raw
      end
    end

    def test_suricata_numbers_one_as_most_severe
      assert_equal 'high',   SystemLog.severity('inner_alert_severity' => 1)
      assert_equal 'medium', SystemLog.severity('inner_alert_severity' => 2)
      assert_equal 'low',    SystemLog.severity('inner_alert_severity' => 3)
    end

    # An entry with no severity must not pass a `--severity` filter: unknown
    # is not evidence of low.
    def test_an_entry_without_a_severity_ranks_below_every_filter
      assert_nil SystemLog.severity({})
      assert_equal 0, SystemLog.rank({})
      assert_equal 3, SystemLog.rank(v2)
    end

    def test_an_unrecognised_severity_is_passed_through_lowercased
      assert_equal 'purple', SystemLog.severity('severity' => 'PURPLE')
      assert_equal 0, SystemLog.rank('severity' => 'PURPLE')
    end

    # --- time and status ------------------------------------------------------

    def test_times_come_from_either_shape
      expected = Time.at(1_788_616_693)

      assert_equal expected, SystemLog.time(v2)
      assert_equal expected, SystemLog.time('time' => 1_788_616_693_564)
      assert_equal Time.utc(2026, 3, 4, 5, 6), SystemLog.time('datetime' => '2026-03-04T05:06:00Z')
      assert_nil SystemLog.time({})
    end

    def test_archived_is_read_from_the_status_or_the_legacy_flag
      refute SystemLog.archived?(v2)
      assert SystemLog.archived?(v2('status' => 'ARCHIVED'))
      assert SystemLog.archived?('archived' => true)
      refute SystemLog.archived?('archived' => false)
    end
  end
end
