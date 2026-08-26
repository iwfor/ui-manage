require_relative '../test_helper'

module UiManage
  module Audit
    class SeverityTest < TestCase
      def test_severities_order_least_to_most_severe
        assert_operator Severity.rank(:critical), :>, Severity.rank(:high)
        assert_operator Severity.rank(:high), :>, Severity.rank(:medium)
        assert_operator Severity.rank(:medium), :>, Severity.rank(:low)
        assert_operator Severity.rank(:low), :>, Severity.rank(:info)
      end

      def test_severities_are_accepted_as_strings_or_symbols
        assert_equal Severity.rank(:high), Severity.rank('HIGH')
      end

      def test_at_or_above_includes_the_floor_itself
        assert Severity.at_or_above?(:high, :high)
        assert Severity.at_or_above?(:critical, :high)
        refute Severity.at_or_above?(:medium, :high)
      end

      def test_an_unknown_severity_is_rejected
        assert_raises(ArgumentError) { Severity.rank(:catastrophic) }
      end
    end

    class FindingTest < TestCase
      def finding(**args)
        Finding.new(**{ check_id: :demo, severity: :high, message: 'bad' }.merge(args))
      end

      def test_a_finding_with_a_subject_is_keyed_by_check_and_subject
        assert_equal 'demo:Guest', finding(subject: 'Guest').key
      end

      def test_a_finding_without_a_subject_is_keyed_by_check_alone
        assert_equal 'demo', finding.key
      end

      def test_a_finding_serialises_without_empty_fields
        assert_equal %w[check severity message], finding.to_h.keys
      end
    end

    class ResultTest < TestCase
      # Registry.find loads the check files; the constant does not exist
      # until then.
      def check = Registry.find(:device_offline)

      def test_the_four_states_are_distinguishable
        assert Result.pass(check).passed?
        assert Result.fail(check, []).failed?
        assert Result.skip(check, 'why').skipped?
        assert Result.error(check, 'boom').errored?
      end

      def test_a_result_reports_its_worst_finding
        findings = [Finding.new(check_id: :d, severity: :low, message: 'a'),
                    Finding.new(check_id: :d, severity: :critical, message: 'b'),
                    Finding.new(check_id: :d, severity: :medium, message: 'c')]

        assert_equal :critical, Result.fail(check, findings).severity
      end

      def test_an_unknown_status_is_rejected
        assert_raises(ArgumentError) { Result.new(check: check, status: :maybe) }
      end
    end

    class SettingsTest < TestCase
      def test_built_in_thresholds_are_available_without_a_file
        assert_equal 80, Settings.new(path: nil).threshold('cpu_percent')
      end

      def test_an_unknown_threshold_names_the_ones_that_exist
        error = assert_raises(ArgumentError) { Settings.new(path: nil).threshold('nope') }

        assert_includes error.message, 'cpu_percent'
      end

      def test_a_file_overrides_only_the_thresholds_it_names
        settings = with_settings_file(<<~TOML)
          [thresholds]
          cpu_percent = 42
        TOML

        assert_equal 42, settings.threshold('cpu_percent')
        assert_equal 85, settings.threshold('memory_percent')
      end

      def test_checks_can_be_suppressed_wholesale
        settings = with_settings_file(<<~TOML)
          [suppress]
          checks = ["wlan_passphrase"]
        TOML

        assert settings.suppressed_check?(:wlan_passphrase)
        refute settings.suppressed_check?(:wlan_encryption)
      end

      def test_a_single_finding_can_be_suppressed_by_subject
        settings = with_settings_file(<<~TOML)
          [suppress]
          findings = ["wlan_encryption:Guest"]
        TOML
        guest = Finding.new(check_id: :wlan_encryption, severity: :high, subject: 'Guest', message: 'x')
        home  = Finding.new(check_id: :wlan_encryption, severity: :high, subject: 'Home', message: 'x')

        assert settings.suppressed_finding?(guest)
        refute settings.suppressed_finding?(home)
      end

      def test_suppressing_a_check_id_suppresses_all_its_findings
        settings = with_settings_file(<<~TOML)
          [suppress]
          findings = ["wlan_encryption"]
        TOML
        any = Finding.new(check_id: :wlan_encryption, severity: :high, subject: 'Anything', message: 'x')

        assert settings.suppressed_finding?(any)
      end

      def test_an_unreadable_settings_file_is_reported_clearly
        path = File.join(TEST_CONFIG_DIR, 'broken.toml')
        File.write(path, "[thresholds\nbroken")

        error = assert_raises(ArgumentError) { Settings.new(path: path) }
        assert_includes error.message, 'audit settings'
      end

      private

      def with_settings_file(contents)
        path = File.join(TEST_CONFIG_DIR, 'audit.toml')
        File.write(path, contents)
        Settings.new(path: path)
      ensure
        FileUtils.rm_f(path)
      end
    end
  end
end
