module UiManage
  module Audit
    module Checks
      # A live link running at half duplex. Modern equipment negotiates full
      # duplex; half almost always means autonegotiation failed, and the
      # resulting collisions look like intermittent packet loss.
      class PortDuplex < Check
        id          :port_duplex
        title       'Live link negotiated at half duplex'
        category    :health
        severity    :medium
        requires    :devices
        remediation 'Replace the cable and make sure neither end has a manually forced ' \
                    'speed or duplex setting — a forced end and an autonegotiating end ' \
                    'is the usual cause.'

        def run
          data(:devices).each do |device|
            Array(device['port_table']).each do |port|
              next unless port['up']
              next unless port['full_duplex'] == false

              finding(
                subject:  "#{device['name'] || device['mac']}:#{port['port_idx']}",
                message:  "#{device['name'] || device['model']} port #{port['port_idx']}" \
                          "#{port['name'] ? " (#{port['name']})" : ''} is linked at half duplex" \
                          "#{port['speed'] ? " (#{port['speed']} Mbps)" : ''}.",
                evidence: { 'speed_mbps' => port['speed'], 'full_duplex' => false }
              )
            end
          end
        end
      end
    end
  end
end
