module UiManage
  module Audit
    module Checks
      # A passphrase short enough to be worth attacking offline. The WPA
      # handshake can be captured by anyone in range, so passphrase length is
      # the only thing standing between a recording and the key.
      class WlanPassphrase < Check
        id          :wlan_passphrase
        title       'SSID passphrase shorter than the configured minimum'
        category    :security
        severity    :high
        requires    :wlans
        remediation 'Settings > WiFi > (SSID) > Password: use a longer passphrase. ' \
                    'Adjust the bar with min_passphrase_chars in audit.toml.'

        def run
          minimum = threshold('min_passphrase_chars')

          data(:wlans).each do |wlan|
            next unless wlan['enabled']

            passphrase = WlanSecurity.passphrase(wlan)
            next if passphrase.empty? || passphrase.length >= minimum

            # The passphrase itself never reaches a Finding — only its length.
            finding(
              subject:  wlan['name'],
              message:  "#{wlan['name']} has a #{passphrase.length}-character passphrase, " \
                        "below the #{minimum}-character minimum.",
              evidence: { 'length' => passphrase.length, 'minimum' => minimum }
            )
          end
        end
      end
    end
  end
end
