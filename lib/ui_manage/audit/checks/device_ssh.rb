module UiManage
  module Audit
    module Checks
      # SSH to the network devices themselves. Enabled is a judgement call;
      # enabled with a shared password is not, because that password is the
      # same on every adopted device and never rotates on its own.
      class DeviceSsh < Check
        id          :device_ssh
        title       'Device SSH access enabled'
        category    :security
        severity    :medium
        requires    :settings
        remediation 'Settings > System > Advanced > Device SSH Authentication: turn it ' \
                    'off, or switch to keys and remove the shared password.'

        def run
          enabled = setting_value('mgmt', 'x_ssh_enabled')
          return unless enabled

          keys = Array(setting('mgmt')['x_ssh_keys'])

          if keys.empty?
            finding(
              severity: :high,
              message:  'Device SSH is enabled with password authentication and no keys — ' \
                        'the same credential works on every adopted device.',
              evidence: { 'ssh_enabled' => true, 'ssh_keys' => 0 }
            )
          else
            finding(
              severity: :medium,
              message:  "Device SSH is enabled (#{keys.size} key#{'s' if keys.size != 1} configured). " \
                        'Leave it on only if you actually use it.',
              evidence: { 'ssh_enabled' => true, 'ssh_keys' => keys.size }
            )
          end
        end
      end
    end
  end
end
