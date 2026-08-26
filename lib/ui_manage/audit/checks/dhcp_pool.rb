require 'ipaddr'

module UiManage
  module Audit
    module Checks
      # DHCP pools running out of addresses. A full pool does not report an
      # error anywhere obvious — clients simply stop getting leases.
      class DhcpPool < Check
        id          :dhcp_pool_exhaustion
        title       'DHCP pool approaching exhaustion'
        category    :health
        severity    :high
        requires    %i[networks clients]
        remediation 'Settings > Networks > (network) > DHCP Range: widen the range, or ' \
                    'shorten the lease time. Adjust the bar with dhcp_pool_percent in ' \
                    'audit.toml.'

        def run
          limit = threshold('dhcp_pool_percent')
          taken = data(:clients).filter_map { |c| to_int(c['ip']) }

          data(:networks).each do |network|
            next unless network['dhcpd_enabled']

            first = to_int(network['dhcpd_start'])
            last  = to_int(network['dhcpd_stop'])
            next if first.nil? || last.nil? || last < first

            size    = last - first + 1
            in_use  = taken.count { |ip| ip.between?(first, last) }
            percent = in_use.to_f / size * 100
            next if percent <= limit

            finding(
              subject:  network['name'],
              message:  "#{network['name']} has #{in_use} of #{size} DHCP addresses in use " \
                        "(#{percent.round(1)}%), above the #{limit}% threshold.",
              evidence: { 'in_use' => in_use, 'size' => size, 'percent' => percent.round(1),
                          'range' => "#{network['dhcpd_start']}-#{network['dhcpd_stop']}" }
            )
          end
        end

        private

        def to_int(address)
          return nil if address.to_s.empty?

          IPAddr.new(address.to_s).to_i
        rescue IPAddr::Error
          nil
        end
      end
    end
  end
end
