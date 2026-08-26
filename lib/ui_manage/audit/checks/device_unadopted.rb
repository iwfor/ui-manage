module UiManage
  module Audit
    module Checks
      # UniFi hardware on the network that this site has not adopted. Either
      # someone plugged in a device nobody accounted for, or an adoption
      # failed and left a device running with factory credentials.
      class DeviceUnadopted < Check
        id          :device_unadopted
        title       'Device present but not adopted'
        category    :security
        severity    :high
        requires    :devices
        remediation 'Devices > (device) in UniFi Network: adopt it, or find out why it ' \
                    'is on the network. An unadopted device still has factory ' \
                    'credentials.'

        PENDING_ADOPTION = 2
        ADOPTION_FAILED  = 9

        def run
          data(:devices).each do |device|
            state = DeviceState.code(device)
            next unless [PENDING_ADOPTION, ADOPTION_FAILED].include?(state)

            finding(
              subject:  device['name'] || device['mac'],
              severity: state == ADOPTION_FAILED ? :high : :medium,
              message:  "#{device['model'] || 'A device'} at #{device['ip'] || device['mac']} " \
                        "is #{DeviceState.label(device)}.",
              evidence: { 'state' => DeviceState.label(device), 'mac' => device['mac'],
                          'model' => device['model'] }
            )
          end
        end
      end
    end
  end
end
