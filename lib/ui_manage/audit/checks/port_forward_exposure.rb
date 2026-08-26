module UiManage
  module Audit
    module Checks
      # Port forwards that put a sensitive service directly on the internet.
      #
      # Which ports count is a threshold, because the answer is site-specific:
      # a deliberately published SSH bastion is not the same finding as an
      # accidentally exposed database.
      class PortForwardExposure < Check
        id          :port_forward_sensitive
        title       'Port forward exposing a sensitive service to the internet'
        category    :security
        severity    :critical
        requires    :port_forwards
        remediation 'Settings > Firewall & Security > Port Forwarding: remove the rule, ' \
                    'or reach the service over a VPN instead. Adjust which ports count ' \
                    'with sensitive_ports in audit.toml.'

        def run
          sensitive = threshold('sensitive_ports')

          data(:port_forwards).each do |rule|
            next unless rule['enabled']

            exposed = PortSpec.intersection(rule['dst_port'], sensitive) |
                      PortSpec.intersection(rule['fwd_port'], sensitive)
            next if exposed.empty?

            finding(
              subject:  rule['name'],
              message:  "#{rule['name']} forwards #{exposed.sort.join(', ')} from the internet " \
                        "to #{rule['fwd']}.",
              evidence: { 'ports' => exposed.sort, 'destination' => rule['fwd'],
                          'external_port' => rule['dst_port'], 'source' => rule['src'] }
            )
          end
        end
      end
    end
  end
end
