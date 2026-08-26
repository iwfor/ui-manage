module UiManage
  module Audit
    module Checks
      # A port forward reachable from the whole internet rather than from a
      # known source. Restricting the source turns an exposed service into one
      # only reachable from where it is actually used.
      class PortForwardSource < Check
        id          :port_forward_open_source
        title       'Port forward open to any source address'
        category    :security
        severity    :high
        requires    :port_forwards
        remediation 'Settings > Firewall & Security > Port Forwarding > (rule) > ' \
                    'Limit access: name the addresses that need it.'

        ANY = ['', 'any', '0.0.0.0/0', '0.0.0.0'].freeze

        def run
          data(:port_forwards).each do |rule|
            next unless rule['enabled']
            next unless ANY.include?(rule['src'].to_s.strip.downcase)

            finding(
              subject:  rule['name'],
              message:  "#{rule['name']} accepts connections from any source address.",
              evidence: { 'source' => rule['src'].to_s, 'external_port' => rule['dst_port'],
                          'destination' => rule['fwd'] }
            )
          end
        end
      end
    end
  end
end
