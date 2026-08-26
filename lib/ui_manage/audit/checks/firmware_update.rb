module UiManage
  module Audit
    module Checks
      # Devices the controller already knows have a newer firmware available.
      class FirmwareUpdate < Check
        id          :firmware_update_available
        title       'Firmware update available'
        category    :health
        severity    :medium
        requires    :devices
        remediation 'Devices > (device) > Update in UniFi Network, or turn on ' \
                    'automatic updates.'

        def run
          data(:devices).each do |device|
            next unless device['upgradable']

            finding(
              subject:  device['name'] || device['mac'],
              message:  "#{device['name'] || device['model']} is on #{device['version']}; " \
                        "#{device['upgrade_to_firmware'] || 'a newer version'} is available.",
              evidence: { 'current' => device['version'], 'available' => device['upgrade_to_firmware'],
                          'model' => device['model'] }
            )
          end
        end
      end
    end
  end
end
