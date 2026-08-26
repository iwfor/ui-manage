module UiManage
  module Audit
    module Checks
      # Whether the controller is reachable through UniFi's cloud against
      # whether the operator says it should be.
      #
      # This is the check that cannot be decided from the controller alone:
      # remote access is a requirement on one network and an exposure on the
      # next. The answer comes from `ui-manage policy`.
      class RemoteAccess < Check
        id          :remote_access
        title       'Cloud remote access disagrees with the configured policy'
        category    :security
        severity    :medium
        requires    :settings
        remediation 'Settings > System > Advanced > Remote Access on the controller; ' \
                    '`ui-manage policy --remote-access` / `--no-remote-access` to record ' \
                    'what this network is supposed to do.'

        SETTING_KEY = 'super_cloudaccess'.freeze

        def run
          section = setting(SETTING_KEY)
          skip!("the controller does not report a #{SETTING_KEY} setting") if section.nil?

          enabled  = !!section['enabled']
          expected = policy(:remote_access_expected)

          return report_unjudged(enabled) if expected.nil?
          return if enabled == expected

          if enabled
            finding(
              severity: :medium,
              message:  'Cloud remote access is enabled, but this network is configured as not expecting it.',
              evidence: { 'enabled' => true, 'expected' => false }
            )
          else
            finding(
              severity: :low,
              message:  'Cloud remote access is disabled, but this network is configured as expecting it.',
              evidence: { 'enabled' => false, 'expected' => true }
            )
          end
        end

        private

        # With no policy recorded there is nothing to disagree with, so this
        # states the setting and stops short of calling it wrong.
        def report_unjudged(enabled)
          finding(
            severity: :info,
            message:  "Cloud remote access is #{enabled ? 'enabled' : 'disabled'}. No policy is " \
                      'recorded for this network — set one with `ui-manage policy`.',
            evidence: { 'enabled' => enabled, 'expected' => nil }
          )
        end
      end
    end
  end
end
