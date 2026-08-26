module UiManage
  module Audit
    module Checks
      # An enabled accept rule with no source and no destination restriction
      # matches everything, and every rule below it in the same ruleset never
      # runs.
      class FirewallPermissive < Check
        id          :firewall_permissive_rule
        title       'Firewall rule accepting any source to any destination'
        category    :security
        severity    :critical
        requires    :firewall_rules
        remediation 'Settings > Firewall & Security > Firewall Rules: narrow the ' \
                    'source or destination, or delete the rule if it was a temporary ' \
                    'diagnostic that stayed.'

        # A wide-open accept from the internet is categorically worse than one
        # between internal networks.
        WAN_RULESETS = %w[WAN_IN WAN_LOCAL WANv6_IN WANv6_LOCAL].freeze

        def run
          data(:firewall_rules).each do |rule|
            next unless rule['enabled']
            next unless rule['action'].to_s.casecmp?('accept')
            next unless unrestricted?(rule, 'src') && unrestricted?(rule, 'dst')

            from_wan = WAN_RULESETS.include?(rule['ruleset'].to_s)
            finding(
              subject:  rule['name'],
              severity: from_wan ? :critical : :high,
              message:  "#{rule['name']} (#{rule['ruleset']}) accepts any source to any " \
                        "destination#{from_wan ? ', from the internet' : ''}.",
              evidence: { 'ruleset' => rule['ruleset'], 'index' => rule['rule_index'] || rule['index'],
                          'protocol' => rule['protocol'] || 'all' }
            )
          end
        end

        private

        # A direction is unrestricted when it names no address, no firewall
        # group, and no network.
        def unrestricted?(rule, direction)
          rule["#{direction}_address"].to_s.strip.empty? &&
            Array(rule["#{direction}_firewallgroup_ids"]).empty? &&
            rule["#{direction}_networkconf_id"].to_s.strip.empty?
        end
      end
    end
  end
end
