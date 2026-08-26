module UiManage
  module Audit
    module Checks
      # Devices running hot. Heat is the thing that turns a working switch
      # into a failing one months later, and it is almost always fixable —
      # a blocked vent, a closed cabinet, a fan that stopped.
      class DeviceTemperature < Check
        id          :device_temperature
        title       'Device temperature above threshold'
        category    :health
        severity    :high
        requires    :devices
        remediation 'Check airflow and ambient temperature around the device. Adjust ' \
                    'the bar with temperature_celsius in audit.toml.'

        def run
          limit    = threshold('temperature_celsius')
          devices  = data(:devices).select { |d| DeviceState.connected?(d) }
          reported = devices.select { |d| readings(d).any? }

          # Most UniFi hardware reports no temperature at all. Passing the
          # check would claim everything is cool; skipping says nothing was
          # measured.
          skip!('no device reports a temperature') if reported.empty?

          reported.each do |device|
            hottest = readings(device).max_by { |_, value| value }
            next if hottest.last <= limit

            finding(
              subject:  device['name'] || device['mac'],
              message:  "#{device['name'] || device['model']} is at #{hottest.last.round(1)}°C " \
                        "(#{hottest.first}), above the #{limit}°C threshold.",
              evidence: { 'celsius' => hottest.last.round(1), 'sensor' => hottest.first,
                          'threshold' => limit }
            )
          end
        end

        private

        # Newer firmware reports a named sensor array; older reports a single
        # figure under one of a couple of keys.
        def readings(device)
          named = Array(device['temperatures']).filter_map do |sensor|
            value = sensor['value']
            [sensor['name'] || 'sensor', value.to_f] if value
          end
          return named if named.any?

          %w[general_temperature temperature].filter_map do |key|
            ['device', device[key].to_f] if device[key]
          end
        end
      end
    end
  end
end
