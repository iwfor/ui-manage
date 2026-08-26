require 'toml-rb'

module UiManage
  module Audit
    # Thresholds and suppressions, read from ~/.config/ui-manage/audit.toml.
    #
    # Thresholds exist because "too high" is site-specific. Suppressions exist
    # because a finding the operator has considered and accepted should stop
    # reappearing — otherwise a recurring known-good finding trains people to
    # ignore the whole report.
    class Settings
      FILE = File.join(CONFIG_DIR, 'audit.toml')

      DEFAULT_THRESHOLDS = {
        # Device health
        'cpu_percent'          => 80,
        'memory_percent'       => 85,
        'temperature_celsius'  => 80,
        'storage_percent'      => 85,
        'poe_budget_percent'   => 85,
        'recent_reboot_hours'  => 1,

        # Uplink
        'wan_latency_ms'       => 100,
        'wan_loss_percent'     => 2,

        # Wireless
        'min_rssi_dbm'         => -72,
        'max_retry_percent'    => 20,
        'channel_util_percent' => 60,

        # Errors as a percentage of packets, rather than a raw count:
        # counters are cumulative since boot, so a long-running device
        # accumulates a few harmlessly.
        'port_error_rate_percent' => 0.1,

        # Addressing
        'dhcp_pool_percent'    => 85,

        # Credentials
        'min_passphrase_chars' => 12,
        'max_super_admins'     => 2,
        'admin_idle_days'      => 90,

        # Operations
        'backup_age_days'      => 7,

        # Ports that should never be reachable from the internet.
        'sensitive_ports'      => [22, 23, 135, 139, 445, 1433, 3306, 3389,
                                   5432, 5900, 6379, 9200, 27017]
      }.freeze

      attr_reader :thresholds

      def initialize(path: FILE, thresholds: {}, suppressed_checks: [], suppressed_findings: [])
        file = load_file(path)

        @thresholds          = DEFAULT_THRESHOLDS.merge(stringify(file['thresholds'])).merge(stringify(thresholds))
        @suppressed_checks   = (Array(file.dig('suppress', 'checks')) + suppressed_checks).map(&:to_s)
        @suppressed_findings = (Array(file.dig('suppress', 'findings')) + suppressed_findings).map(&:to_s)
      end

      def threshold(name)
        @thresholds.fetch(name.to_s) do
          raise ArgumentError, "No threshold named #{name.inspect}. Known: #{@thresholds.keys.sort.join(', ')}"
        end
      end

      def suppressed_check?(id) = @suppressed_checks.include?(id.to_s)

      # A finding is suppressed by its own "check:subject" key, or by its
      # check id when every finding from that check is being ignored.
      def suppressed_finding?(finding)
        @suppressed_findings.include?(finding.key) ||
          @suppressed_findings.include?(finding.check_id.to_s)
      end

      def self.example_file
        <<~TOML
          # Thresholds the audit compares against. Anything not listed here
          # uses the built-in default.
          [thresholds]
          cpu_percent = 80
          min_passphrase_chars = 12

          [suppress]
          # Whole checks to stop running.
          checks = []
          # Individual findings, as "check_id" or "check_id:subject".
          findings = []
        TOML
      end

      private

      def load_file(path)
        return {} unless path && File.exist?(path)

        TomlRB.load_file(path)
      rescue StandardError => e
        raise ArgumentError, "Could not read audit settings (#{path}): #{e.message}"
      end

      def stringify(hash) = (hash || {}).transform_keys(&:to_s)
    end
  end
end
