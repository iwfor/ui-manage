module UiManage
  module Audit
    module Checks
      # Firmware updates that will not install themselves. Network gear tends
      # to be forgotten between incidents, which is exactly how a device ends
      # up years behind on a remotely exploitable bug.
      class AutoUpdates < Check
        id          :auto_firmware_updates
        title       'Automatic firmware updates disabled'
        category    :security
        severity    :medium
        requires    :settings
        remediation 'Settings > System > Updates: enable automatic updates, or set a ' \
                    'reminder to apply them on a schedule you will keep.'

        def run
          enabled = setting_value('auto_upgrade', 'enabled', 'auto_upgrade')
          return if enabled

          finding(
            message:  'Automatic firmware updates are disabled; devices will stay on ' \
                      'their current version until someone intervenes.',
            evidence: { 'auto_upgrade' => false }
          )
        end
      end
    end
  end
end
