module UiManage
  module Audit
    module Checks
      # A drop or reject rule with logging off still protects the network, but
      # leaves nothing to look at afterwards — which is when you most want it.
      class FirewallLogging < Check
        id          :firewall_rule_logging
        title       'Blocking firewall rule without logging'
        category    :security
        severity    :low
        requires    :firewall_rules
        remediation 'Settings > Firewall & Security > Firewall Rules > (rule) > Logging. ' \
                    'Worth enabling at least on rules facing the internet.'

        BLOCKING = %w[drop reject].freeze

        def run
          rules = data(:firewall_rules).select do |rule|
            rule['enabled'] && BLOCKING.include?(rule['action'].to_s.downcase) && !rule['logging']
          end
          return if rules.empty?

          # One finding rather than one per rule: on most sites this is a
          # setting applied consistently, and a finding per rule would bury
          # everything else.
          finding(
            message:  "#{rules.size} blocking firewall rule#{'s' if rules.size != 1} " \
                      "#{rules.size == 1 ? 'has' : 'have'} logging disabled, so blocked " \
                      'traffic leaves no record.',
            evidence: { 'count' => rules.size, 'rules' => rules.first(10).map { |r| r['name'] } }
          )
        end
      end
    end
  end
end
