module UiManage
  module Audit
    module Checks
      # An access point this site does not manage, broadcasting one of its
      # SSIDs. Clients configured for that network will associate with it
      # given a stronger signal, which is the whole point of the attack.
      class RogueApImpersonation < Check
        id          :rogue_ap_impersonation
        title       'Unmanaged access point broadcasting one of our SSIDs'
        category    :security
        severity    :critical
        requires    %i[rogue_aps wlans]
        remediation 'Locate the access point by signal strength and remove it. If it ' \
                    'is yours, adopt it so it stops reading as unmanaged.'

        def run
          ours = WlanSecurity.ssid_names(data(:wlans))

          data(:rogue_aps).each do |ap|
            essid = ap['essid'].to_s
            next unless WlanSecurity.impersonates?(essid, ours)

            signal = ap['signal'] || ap['rssi']
            finding(
              subject:  ap['bssid'],
              message:  "#{ap['bssid']} is broadcasting '#{essid}', one of this site's SSIDs, " \
                        "and is not managed here#{signal ? " (#{signal} dBm)" : ''}.",
              evidence: { 'essid' => essid, 'bssid' => ap['bssid'],
                          'channel' => ap['channel'], 'signal' => signal }
            )
          end
        end
      end
    end
  end
end
