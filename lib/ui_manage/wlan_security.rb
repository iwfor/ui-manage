module UiManage
  # Classifies a WLAN's security configuration.
  #
  # Lives outside both the views and the audit checks because both need the
  # same answer: `wlans` prints the label, and the audit turns the weaknesses
  # into findings. One implementation means they can never disagree about
  # what counts as insecure.
  module WlanSecurity
    # Why a WLAN is considered weak, in the order a reader should act on them.
    WEAKNESSES = {
      open: 'no encryption at all — every frame is readable by anyone in range',
      wep:  'WEP, broken since 2001 and recoverable in minutes',
      wpa1: 'WPA1, deprecated and vulnerable to practical downgrade attacks',
      tkip: 'TKIP, the WPA1-era cipher, kept alive only for legacy clients',
      wps:  'WPS, whose PIN exchange is brute-forceable'
    }.freeze

    module_function

    # How the security mode should read in output, e.g. "WPA2-PSK", "OPEN".
    def label(wlan)
      case wlan['security'].to_s.downcase
      when 'open', '' then 'OPEN'
      when 'wep'      then 'WEP'
      when 'wpaeap'   then "#{generation(wlan)}-Enterprise"
      else                 "#{generation(wlan)}-PSK"
      end
    end

    def generation(wlan)
      return 'WPA3' if wlan['wpa3_support'] || wlan['wpa3_enhanced_192']
      return 'WPA3/WPA2' if wlan['wpa3_transition']

      case wlan['wpa_mode'].to_s.downcase
      when 'wpa1', 'wpa' then 'WPA1'
      when 'wpa3'        then 'WPA3'
      else                    'WPA2'
      end
    end

    # Every reason this WLAN is weak, as symbols keyed into WEAKNESSES.
    def weaknesses(wlan)
      found    = []
      security = wlan['security'].to_s.downcase

      found << :open if security == 'open' || security.empty?
      found << :wep  if security == 'wep'
      found << :wpa1 if generation(wlan) == 'WPA1'
      found << :tkip if wlan['wpa_enc'].to_s.casecmp?('tkip')
      found << :wps  if wlan['wps']
      found
    end

    def insecure?(wlan) = weaknesses(wlan).any?

    def describe(weakness) = WEAKNESSES.fetch(weakness)

    # Protected Management Frames, which stop deauthentication attacks. UniFi
    # reports 'disabled', 'optional', or 'required'.
    def pmf_mode(wlan) = (wlan['pmf_mode'] || 'disabled').to_s

    def passphrase(wlan) = wlan['x_passphrase'].to_s
  end
end
