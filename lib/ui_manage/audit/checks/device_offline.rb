module UiManage
  module Audit
    module Checks
      # Adopted devices that are not currently connected.
      class DeviceOffline < Check
        id          :device_offline
        title       'Adopted device not connected'
        category    :health
        severity    :critical
        requires    :devices
        remediation 'Check the device power and uplink, then Devices > (device) in ' \
                    'UniFi Network for its adoption state.'

        # A device mid-upgrade or mid-provision is briefly not "connected" by
        # design; reporting those would make the check noise.
        TRANSIENT = [4, 5, 7].freeze

        def run
          data(:devices).each do |device|
            next if DeviceState.connected?(device)
            next if TRANSIENT.include?(DeviceState.code(device))

            finding(
              subject:  device['name'] || device['mac'],
              message:  "#{device['name'] || device['model']} is #{DeviceState.label(device)}.",
              evidence: { 'state' => DeviceState.label(device), 'model' => device['model'] }
            )
          end
        end
      end
    end
  end
end
