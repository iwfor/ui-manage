require 'ipaddr'

module UiManage
  module Audit
    module Checks
      # Fixed IP reservations that will not do what they look like they do:
      # two clients reserving the same address, or a reservation pointing
      # outside the network it belongs to.
      class DhcpReservation < Check
        id          :dhcp_reservation
        title       'Conflicting or out-of-range DHCP reservation'
        category    :health
        severity    :high
        requires    %i[dhcp_leases networks]
        remediation 'Settings > Client Devices > (client) > Fixed IP: give each client a ' \
                    'distinct address inside its own network.'

        def run
          reserved = data(:dhcp_leases).select { |lease| lease['use_fixedip'] && lease['fixed_ip'] }

          report_duplicates(reserved)
          report_out_of_range(reserved)
        end

        private

        def report_duplicates(reserved)
          reserved.group_by { |lease| lease['fixed_ip'] }.each do |address, leases|
            next if leases.size < 2

            finding(
              subject:  address,
              message:  "#{leases.size} clients reserve #{address}: " \
                        "#{leases.map { |l| l['name'] || l['hostname'] || l['mac'] }.join(', ')}.",
              evidence: { 'address' => address, 'macs' => leases.map { |l| l['mac'] } }
            )
          end
        end

        def report_out_of_range(reserved)
          networks = data(:networks).each_with_object({}) do |network, map|
            subnet = parse(network['ip_subnet'])
            map[network['_id']] = [network, subnet] if subnet
          end

          reserved.each do |lease|
            network, subnet = networks[lease['network_id']]
            next if network.nil?

            address = parse(lease['fixed_ip'])
            next if address.nil? || subnet.include?(address)

            name = lease['name'] || lease['hostname'] || lease['mac']
            finding(
              subject:  name,
              message:  "#{name} reserves #{lease['fixed_ip']}, which is outside " \
                        "#{network['name']} (#{network['ip_subnet']}).",
              evidence: { 'address' => lease['fixed_ip'], 'network' => network['name'],
                          'subnet' => network['ip_subnet'] }
            )
          end
        end

        def parse(address)
          return nil if address.to_s.empty?

          IPAddr.new(address.to_s)
        rescue IPAddr::Error
          nil
        end
      end
    end
  end
end
