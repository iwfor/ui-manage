module UiManage
  module Audit
    module Checks
      # A device that restarted recently without anyone asking it to. One is
      # worth a glance; a device that keeps appearing here is failing.
      class DeviceRecentReboot < Check
        id          :device_recent_reboot
        title       'Device restarted recently'
        category    :health
        severity    :medium
        requires    :devices
        remediation 'Check the device event log under Devices > (device) > Insights. ' \
                    'Repeated restarts usually mean power delivery or heat. Adjust the ' \
                    'window with recent_reboot_hours in audit.toml.'

        def run
          hours   = threshold('recent_reboot_hours')
          seconds = hours * 3600

          data(:devices).each do |device|
            next unless DeviceState.connected?(device)

            uptime = device['uptime'].to_i
            next if uptime.zero? || uptime >= seconds

            finding(
              subject:  device['name'] || device['mac'],
              message:  "#{device['name'] || device['model']} has been up for only " \
                        "#{(uptime / 60.0).round} minutes.",
              evidence: { 'uptime_seconds' => uptime, 'window_hours' => hours }
            )
          end
        end
      end
    end
  end
end
