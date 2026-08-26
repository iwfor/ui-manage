module UiManage
  module Audit
    module Checks
      # Memory pressure on a network device, which shows up as dropped
      # sessions and failed provisioning before the device actually restarts.
      class DeviceMemory < Check
        id          :device_memory
        title       'Device memory above threshold'
        category    :health
        severity    :high
        requires    :devices
        remediation 'Devices > (device) > Insights. Sustained pressure usually means ' \
                    'the device is undersized for the client count. Adjust the bar ' \
                    'with memory_percent in audit.toml.'

        def run
          limit = threshold('memory_percent')

          data(:devices).each do |device|
            next unless DeviceState.connected?(device)

            percent = memory_percent(device)
            next if percent.nil? || percent <= limit

            finding(
              subject:  device['name'] || device['mac'],
              message:  "#{device['name'] || device['model']} memory is at #{percent.round(1)}%, " \
                        "above the #{limit}% threshold.",
              evidence: { 'memory_percent' => percent.round(1), 'threshold' => limit }
            )
          end
        end

        private

        # Devices report memory either as a ready-made percentage under
        # system-stats or as raw totals under sys_stats.
        def memory_percent(device)
          if (percent = device.dig('system-stats', 'mem')) && !percent.to_s.empty?
            return percent.to_f
          end

          total = device.dig('sys_stats', 'mem_total').to_i
          used  = device.dig('sys_stats', 'mem_used').to_i
          return nil if total.zero?

          used.to_f / total * 100
        end
      end
    end
  end
end
