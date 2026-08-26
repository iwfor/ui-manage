require 'ipaddr'

module UiManage
  module Audit
    module Checks
      # Two networks configured on overlapping address ranges. Routing between
      # them becomes ambiguous, and the symptom — some hosts unreachable some
      # of the time — is hard to trace back to the cause.
      class SubnetOverlap < Check
        id          :subnet_overlap
        title       'Networks configured on overlapping subnets'
        category    :health
        severity    :high
        requires    :networks
        remediation 'Settings > Networks: renumber one of the two onto its own range.'

        def run
          subnets = data(:networks).filter_map do |network|
            next unless network['enabled'] != false

            range = parse(network['ip_subnet'])
            [network, range] if range
          end

          subnets.combination(2).each do |(first, first_range), (second, second_range)|
            next unless overlap?(first_range, second_range)

            finding(
              subject:  "#{first['name']} / #{second['name']}",
              message:  "#{first['name']} (#{first['ip_subnet']}) overlaps " \
                        "#{second['name']} (#{second['ip_subnet']}).",
              evidence: { 'networks' => [first['name'], second['name']],
                          'subnets' => [first['ip_subnet'], second['ip_subnet']] }
            )
          end
        end

        private

        def parse(subnet)
          return nil if subnet.to_s.empty?

          IPAddr.new(subnet.to_s)
        rescue IPAddr::Error
          nil
        end

        # include? on the wider of the two catches containment in either
        # direction, which is what overlap means for CIDR ranges.
        def overlap?(first, second)
          return false unless first.family == second.family

          first.include?(second) || second.include?(first)
        end
      end
    end
  end
end
