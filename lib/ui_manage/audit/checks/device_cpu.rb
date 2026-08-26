module UiManage
  module Audit
    module Checks
      # Sustained CPU load on a network device, which shows up as latency and
      # dropped frames long before the device actually fails.
      class DeviceCpu < Check
        id          :device_cpu
        title       'Device CPU above threshold'
        category    :health
        severity    :high
        requires    :devices
        remediation 'Devices > (device) > Insights in UniFi Network. Adjust the bar ' \
                    'with cpu_percent in audit.toml.'

        def run
          limit = threshold('cpu_percent')

          data(:devices).each do |device|
            next unless DeviceState.connected?(device)

            cpu = device.dig('system-stats', 'cpu')
            next if cpu.nil? || cpu.to_s.empty?
            next if cpu.to_f <= limit

            finding(
              subject:  device['name'] || device['mac'],
              message:  "#{device['name'] || device['model']} CPU is at #{cpu.to_f.round(1)}%, " \
                        "above the #{limit}% threshold.",
              evidence: { 'cpu_percent' => cpu.to_f.round(1), 'threshold' => limit }
            )
          end
        end
      end
    end
  end
end
