module UiManage
  # Turns the options a user gives for a wireless network into the attribute
  # hash the controller stores. Pure functions, like NetworkConfig, so the
  # mapping from "wpa3" to the four fields that actually mean WPA3 lives in
  # one tested place.
  #
  # The security modes map onto the same fields WlanSecurity reads back, so
  # what `wlan-set --security wpa3` writes is what `wlans` will then label
  # WPA3-PSK.
  module WlanConfig
    class Invalid < ArgumentError; end

    # Security modes by name. WPA3 requires protected management frames, so
    # setting it also sets PMF unless the caller chose a PMF mode; the
    # controller rejects WPA3 without it.
    SECURITY = {
      'open' => { 'security' => 'open', 'wpa3_support' => false, 'wpa3_transition' => false },
      'wpa2' => { 'security' => 'wpapsk', 'wpa_mode' => 'wpa2', 'wpa_enc' => 'ccmp',
                  'wpa3_support' => false, 'wpa3_transition' => false },
      'wpa3' => { 'security' => 'wpapsk', 'wpa_mode' => 'wpa2', 'wpa_enc' => 'ccmp',
                  'wpa3_support' => true, 'wpa3_transition' => false, 'pmf_mode' => 'required' },
      # WPA2 and WPA3 side by side, for a mix of old and new clients.
      'wpa2-wpa3' => { 'security' => 'wpapsk', 'wpa_mode' => 'wpa2', 'wpa_enc' => 'ccmp',
                       'wpa3_support' => true, 'wpa3_transition' => true, 'pmf_mode' => 'optional' }
    }.freeze

    PMF_MODES = %w[disabled optional required].freeze

    BANDS = %w[2g 5g 6g].freeze

    # Aliases a user is likely to type for a band.
    BAND_ALIASES = { '2.4' => '2g', '2.4g' => '2g', '2.4ghz' => '2g', '5' => '5g', '5ghz' => '5g',
                     '6' => '6g', '6ghz' => '6g' }.freeze

    module_function

    # Only the fields for the options actually given (nil means "not given").
    def attributes(name: nil, network_id: nil, guest: nil, isolate: nil, pmf: nil, hidden: nil,
                   enabled: nil, band: nil, security: nil, passphrase: nil)
      attrs = {}
      attrs['name']           = validated_name(name)  unless name.nil?
      attrs['networkconf_id'] = network_id            unless network_id.nil?
      attrs['is_guest']       = !!guest               unless guest.nil?
      attrs['l2_isolation']   = !!isolate             unless isolate.nil?
      attrs['hide_ssid']      = !!hidden              unless hidden.nil?
      attrs['enabled']        = !!enabled             unless enabled.nil?
      attrs.merge!(band_attributes(band))             unless band.nil?
      attrs.merge!(security_attributes(security))     unless security.nil?
      attrs['pmf_mode']       = validated_pmf(pmf)    unless pmf.nil?
      attrs['x_passphrase']   = validated_passphrase(passphrase, security: security) unless passphrase.nil?
      attrs
    end

    def security_attributes(mode)
      key = mode.to_s.downcase
      SECURITY.fetch(key) do
        raise Invalid, "Security #{mode.inspect} must be one of #{SECURITY.keys.join(', ')}"
      end.dup
    end

    # "2g", "5g", "6g", "all", or a comma-separated combination. The controller
    # keeps both a summary field and the list, so both are written.
    def band_attributes(value)
      names = value.to_s.downcase.split(',').map(&:strip)
      names = BANDS.dup if names == ['all'] || names == ['both']
      names = names.map { |n| BAND_ALIASES.fetch(n, n) }.uniq

      unknown = names - BANDS
      unless unknown.empty? || names.empty?
        raise Invalid, "Band #{value.inspect} must be all, or any of #{BANDS.join(', ')} (comma-separated)"
      end
      raise Invalid, 'Band must not be empty' if names.empty?

      ordered = BANDS & names
      { 'wlan_band' => ordered.size == 1 ? ordered.first : 'both', 'wlan_bands' => ordered }
    end

    def validated_pmf(value)
      mode = value.to_s.downcase
      raise Invalid, "PMF #{value.inspect} must be one of #{PMF_MODES.join(', ')}" unless PMF_MODES.include?(mode)

      mode
    end

    # WPA2/WPA3-Personal passphrases are 8 to 63 printable ASCII characters.
    def validated_passphrase(value, security: nil)
      raise Invalid, 'An open network has no passphrase' if security.to_s.downcase == 'open'

      psk = value.to_s
      raise Invalid, 'Passphrase must be 8 to 63 characters' unless (8..63).cover?(psk.length)
      raise Invalid, 'Passphrase must be printable ASCII' unless psk.match?(/\A[\x20-\x7e]+\z/)

      psk
    end

    def validated_name(value)
      name = value.to_s
      raise Invalid, 'SSID must be 1 to 32 characters' unless (1..32).cover?(name.bytesize)

      name
    end

    # How a change reads back to the user, one line per field, without ever
    # echoing the passphrase.
    def describe(attrs)
      attrs.map do |key, value|
        case key
        when 'x_passphrase'   then 'passphrase: updated'
        when 'networkconf_id' then nil # the caller names the network
        when 'wlan_bands'     then nil # summarised by wlan_band
        when 'wlan_band'      then "band: #{value == 'both' ? attrs['wlan_bands'].join('+') : value}"
        else "#{key}: #{value}"
        end
      end.compact
    end
  end
end
