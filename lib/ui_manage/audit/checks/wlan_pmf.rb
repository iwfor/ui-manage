module UiManage
  module Audit
    module Checks
      # Protected Management Frames, without which anyone in range can forge
      # deauthentication frames and knock clients off the network at will —
      # which is also the first step in capturing a handshake to attack
      # offline.
      class WlanPmf < Check
        id          :wlan_pmf
        title       'SSID without protected management frames'
        category    :security
        severity    :medium
        requires    :wlans
        remediation 'Settings > WiFi > (SSID) > Advanced > PMF: set to required ' \
                    'where clients allow it, optional otherwise.'

        def run
          data(:wlans).each do |wlan|
            next unless wlan['enabled']

            # An open network has no management frame protection to enable,
            # and is already reported by wlan_encryption.
            next if WlanSecurity.weaknesses(wlan).include?(:open)
            next unless WlanSecurity.pmf_mode(wlan) == 'disabled'

            finding(
              subject:  wlan['name'],
              message:  "#{wlan['name']} has protected management frames disabled, " \
                        'leaving clients open to forged deauthentication.',
              evidence: { 'pmf_mode' => 'disabled', 'security' => WlanSecurity.label(wlan) }
            )
          end
        end
      end
    end
  end
end
