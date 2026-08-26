module UiManage
  module Audit
    module Checks
      # Intrusion prevention that is off, or watching without acting.
      class IpsDisabled < Check
        id          :ips_disabled
        title       'Intrusion prevention disabled or in detect-only mode'
        category    :security
        severity    :high
        requires    :settings
        remediation 'Settings > Firewall & Security > Threat Management: enable it and ' \
                    'set the mode to detect and block.'

        DETECT_ONLY = %w[detect ids].freeze
        BLOCKING    = %w[ips detect_and_block block].freeze

        def run
          mode = setting_value('ips', 'ips_mode', 'enabled').to_s

          if mode.empty? || mode == 'false' || mode == 'disabled'
            finding(
              severity: :high,
              message:  'Threat management is disabled — nothing is inspecting traffic for ' \
                        'known attacks.',
              evidence: { 'mode' => mode.empty? ? 'disabled' : mode }
            )
          elsif DETECT_ONLY.include?(mode)
            finding(
              severity: :medium,
              message:  'Threat management is in detect-only mode: it records attacks but ' \
                        'does not block them.',
              evidence: { 'mode' => mode }
            )
          elsif !BLOCKING.include?(mode) && mode != 'true'
            skip!("the controller reports an unrecognised threat management mode (#{mode})")
          end
        end
      end
    end
  end
end
