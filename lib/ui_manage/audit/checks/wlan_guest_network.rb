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
        remediation 'Settings > Networks: give the guest SSID its own network with ' \
                    'purpose "Guest", which applies client isolation and blocks ' \
                    'access to other networks.'

        def run
          networks = data(:networks).each_with_object({}) { |n, h| h[n['_id']] = n }

          data(:wlans).each do |wlan|
            next unless wlan['enabled'] && wlan['is_guest']

            network = networks[wlan['networkconf_id']]
            next if network.nil? # no mapping to judge
            next if guest_network?(network)

            finding(
              subject:  wlan['name'],
              message:  "#{wlan['name']} is a guest SSID but maps to '#{network['name']}', " \
                        "a #{network['purpose'] || 'non-guest'} network — guest clients are " \
                        'not isolated from it.',
              evidence: { 'network' => network['name'], 'purpose' => network['purpose'],
                          'vlan' => network['vlan'] }
            )
          end
        end

        private

        def guest_network?(network)
          network['purpose'].to_s == 'guest' ||
            network['is_guest'] ||
            network['network_isolation_enabled']
        end
      end
    end
  end
end
