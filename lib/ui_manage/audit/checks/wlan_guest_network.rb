module UiManage
  module Audit
    module Checks
      # A guest SSID landing on an ordinary network rather than a guest one.
      #
      # The guest flag on a WLAN controls the portal; the network it maps to
      # controls whether those clients can reach everything else. Setting the
      # first without the second is the common way a "guest" network ends up
      # with full LAN access.
      class WlanGuestNetwork < Check
        id          :wlan_guest_network
        title       'Guest SSID on a network without guest treatment'
        category    :security
        severity    :high
        requires    %i[wlans networks]
        remediation 'Give the guest SSID its own network in the Hotspot firewall zone ' \
                    '(or, before Network 9, with purpose "Guest"), which blocks access ' \
                    'to other networks: `ui-manage vlan-create Guest --vlan N --subnet ' \
                    'X --guest`, then `ui-manage wlan-set SSID --network Guest --guest`.'

        def run
          networks = data(:networks).each_with_object({}) { |n, h| h[n['_id']] = n }
          # Zones only exist on Network 9+; without them the legacy fields
          # on the network are all there is to judge by.
          zones    = FirewallZone.by_network(data(:firewall_zones))

          data(:wlans).each do |wlan|
            next unless wlan['enabled'] && wlan['is_guest']

            network = networks[wlan['networkconf_id']]
            next if network.nil? # no mapping to judge
            next if guest_network?(network, zones[network['_id']])

            finding(
              subject:  wlan['name'],
              message:  "#{wlan['name']} is a guest SSID but maps to '#{network['name']}', " \
                        "a #{network['purpose'] || 'non-guest'} network — guest clients are " \
                        'not isolated from it.',
              evidence: { 'network' => network['name'], 'purpose' => network['purpose'],
                          'vlan' => network['vlan'], 'zone' => zones.dig(network['_id'], 'name') }.compact
            )
          end
        end

        private

        def guest_network?(network, zone)
          network['purpose'].to_s == 'guest' ||
            network['is_guest'] ||
            network['network_isolation_enabled'] ||
            FirewallZone.guest?(zone)
        end
      end
    end
  end
end
