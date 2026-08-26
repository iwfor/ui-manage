module UiManage
  module Audit
    module Checks
      # Ports accumulating errors or drops.
      #
      # Judged as a rate rather than a count: the counters are cumulative
      # since the device booted, so a device up for a year collects a few
      # harmlessly, and a raw threshold would either miss a failing port on a
      # fresh device or flag every healthy port on an old one.
      class PortErrors < Check
        id          :port_errors
        title       'Switch port error rate above threshold'
        category    :health
        severity    :medium
        requires    :devices
        remediation 'Usually the cable or the far-end port. Reseat or replace the cable, ' \
                    'then clear the counters by reconnecting. Adjust the bar with ' \
                    'port_error_rate_percent in audit.toml.'

        ERROR_KEYS  = %w[rx_errors tx_errors].freeze
        PACKET_KEYS = %w[rx_packets tx_packets].freeze

        def run
          limit = threshold('port_error_rate_percent')

          data(:devices).each do |device|
            Array(device['port_table']).each do |port|
              next unless port['up']

              packets = PACKET_KEYS.sum { |k| port[k].to_i }
              errors  = ERROR_KEYS.sum { |k| port[k].to_i }
              next if errors.zero? || packets.zero?

              rate = errors.to_f / packets * 100
              next if rate <= limit

              finding(
                subject:  "#{device['name'] || device['mac']}:#{port['port_idx']}",
                message:  "#{device['name'] || device['model']} port #{port['port_idx']}" \
                          "#{port['name'] ? " (#{port['name']})" : ''} has an error rate of " \
                          "#{rate.round(3)}%, above the #{limit}% threshold.",
                evidence: { 'error_rate_percent' => rate.round(3), 'errors' => errors,
                            'packets' => packets, 'threshold' => limit }
              )
            end
          end
        end
      end
    end
  end
end
