module UiManage
  module Audit
    module Checks
      # Firewall groups no rule refers to. Harmless in themselves, but they
      # make the ruleset harder to read, and a group that looks like it is
      # restricting something when nothing references it is worse than
      # harmless.
      class FirewallUnusedGroup < Check
        id          :firewall_unused_group
        title       'Firewall group not referenced by any rule'
        category    :security
        severity    :info
        requires    %i[firewall_groups firewall_rules]
        remediation 'Settings > Firewall & Security > Groups: delete the unused group, ' \
                    'or reference it from the rule it was meant for.'

        def run
          referenced = data(:firewall_rules).flat_map do |rule|
            Array(rule['src_firewallgroup_ids']) + Array(rule['dst_firewallgroup_ids'])
          end.uniq

          data(:firewall_groups).each do |group|
            next if referenced.include?(group['_id'])

            finding(
              subject:  group['name'],
              message:  "Firewall group '#{group['name']}' is not referenced by any rule.",
              evidence: { 'type' => group['group_type'],
                          'members' => Array(group['group_members']).size }
            )
          end
        end
      end
    end
  end
end
