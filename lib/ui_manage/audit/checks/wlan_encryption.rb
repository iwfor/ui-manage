module UiManage
  module Audit
    module Checks
      # Any SSID whose encryption is absent, broken, or downgradeable.
      class WlanEncryption < Check
        id          :wlan_encryption
        title       'SSID with absent or broken encryption'
        category    :security
        severity    :critical
        requires    :wlans
        remediation 'Settings > WiFi > (SSID) > Security: use WPA2 or WPA3, ' \
                    'disable WPS, and turn off TKIP compatibility.'

        # WPS is bad but not on the level of an unencrypted network, so it
        # reports one step down rather than dragging the whole SSID to
        # critical.
        SEVERITY_BY_WEAKNESS = { open: :critical, wep: :critical, wpa1: :high, tkip: :high, wps: :high }.freeze

        def run
          data(:wlans).each do |wlan|
            next unless wlan['enabled']

            WlanSecurity.weaknesses(wlan).each do |weakness|
              finding(
                subject:  wlan['name'],
                severity: SEVERITY_BY_WEAKNESS.fetch(weakness, :high),
                message:  "#{wlan['name']} uses #{WlanSecurity.describe(weakness)}.",
                evidence: { 'security' => WlanSecurity.label(wlan), 'weakness' => weakness.to_s }
              )
            end
          end
        end
      end
    end
  end
end
