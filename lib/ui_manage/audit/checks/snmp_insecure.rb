module UiManage
  module Audit
    module Checks
      # SNMP v1 and v2c authenticate with a community string sent in clear
      # text, so anyone who can see the traffic can read the device's
      # configuration and topology.
      class SnmpInsecure < Check
        id          :snmp_insecure
        title       'SNMP v1/v2c enabled, or using a default community string'
        category    :security
        severity    :high
        requires    :settings
        remediation 'Settings > System > Advanced > SNMP: disable v1/v2c and use v3, ' \
                    'or turn SNMP off entirely if nothing polls these devices.'

        DEFAULT_COMMUNITIES = %w[public private community].freeze

        def run
          enabled = setting_value('snmp', 'enabled', 'snmp_v1_enabled', 'community')
          section = setting('snmp')

          legacy = section['enabled'] || section['snmp_v1_enabled'] || section['snmp_v2c_enabled']
          return unless legacy || (enabled.is_a?(String) && !enabled.empty?)

          community = section['community'].to_s

          finding(
            message:  'SNMP v1/v2c is enabled; its community string crosses the network in clear text.',
            evidence: { 'community_is_default' => DEFAULT_COMMUNITIES.include?(community.downcase) }
          )

          return unless DEFAULT_COMMUNITIES.include?(community.downcase)

          # The community string is a credential, so the finding names the
          # fact rather than the value.
          finding(
            severity: :high,
            subject:  'community string',
            message:  'The SNMP community string is one of the well-known defaults.',
            evidence: { 'community_is_default' => true }
          )
        end
      end
    end
  end
end
