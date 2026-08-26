module UiManage
  module Audit
    module Checks
      # UPnP lets any host on the LAN open a hole in the firewall without
      # anyone approving it — which is exactly what malware on a client uses
      # to make itself reachable from outside.
      class UpnpEnabled < Check
        id          :upnp_enabled
        title       'UPnP allows clients to open the firewall themselves'
        category    :security
        severity    :high
        requires    :settings
        remediation 'Settings > Firewall & Security > UPnP: turn it off, and forward ' \
                    'the specific ports anything genuinely needs.'

        def run
          enabled = setting_value('usg', 'upnp_enabled')
          return unless enabled

          finding(
            message:  'UPnP is enabled, so any client can open inbound firewall holes without approval.',
            evidence: { 'upnp_enabled' => true }
          )
        end
      end
    end
  end
end
