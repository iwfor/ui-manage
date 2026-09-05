require_relative 'test_helper'

module UiManage
  class WlanConfigTest < TestCase
    def test_attributes_only_carries_what_was_given
      assert_equal({}, WlanConfig.attributes)
      assert_equal({ 'is_guest' => true }, WlanConfig.attributes(guest: true))
      assert_equal({ 'l2_isolation' => false, 'hide_ssid' => true, 'enabled' => false },
                   WlanConfig.attributes(isolate: false, hidden: true, enabled: false))
    end

    def test_security_modes_write_the_fields_wlan_security_reads_back
      wpa2 = WlanConfig.attributes(security: 'wpa2')
      assert_equal 'WPA2-PSK', WlanSecurity.label(wpa2)
      refute wpa2.key?('pmf_mode')

      wpa3 = WlanConfig.attributes(security: 'WPA3')
      assert_equal 'WPA3-PSK', WlanSecurity.label(wpa3)
      assert_equal 'required', wpa3['pmf_mode']

      both = WlanConfig.attributes(security: 'wpa2-wpa3')
      assert_equal 'WPA3/WPA2-PSK', WlanSecurity.label(both)
      assert_equal 'optional', both['pmf_mode']

      assert_equal 'OPEN', WlanSecurity.label(WlanConfig.attributes(security: 'open'))
      refute WlanSecurity.insecure?(wpa3)
    end

    def test_an_explicit_pmf_mode_wins_over_the_security_default
      attrs = WlanConfig.attributes(security: 'wpa3', pmf: 'optional')

      assert_equal 'optional', attrs['pmf_mode']
    end

    def test_bands_write_both_the_summary_and_the_list
      assert_equal({ 'wlan_band' => '2g', 'wlan_bands' => ['2g'] }, WlanConfig.band_attributes('2g'))
      assert_equal({ 'wlan_band' => '5g', 'wlan_bands' => ['5g'] }, WlanConfig.band_attributes('5GHz'))
      assert_equal({ 'wlan_band' => 'both', 'wlan_bands' => %w[2g 5g 6g] }, WlanConfig.band_attributes('all'))
      assert_equal({ 'wlan_band' => 'both', 'wlan_bands' => %w[2g 5g] }, WlanConfig.band_attributes('5g,2.4'))
    end

    def test_a_passphrase_is_checked_before_it_is_sent
      assert_equal 'correct horse battery', WlanConfig.attributes(passphrase: 'correct horse battery')['x_passphrase']

      assert_includes refused { WlanConfig.attributes(passphrase: 'short') }, '8 to 63'
      assert_includes refused { WlanConfig.attributes(passphrase: 'x' * 64) }, '8 to 63'
      assert_includes refused { WlanConfig.attributes(passphrase: "tab\there!") }, 'printable'
      assert_includes refused { WlanConfig.attributes(security: 'open', passphrase: 'irrelevant') }, 'open'
    end

    def test_bad_values_are_refused_with_a_reason
      assert_includes refused { WlanConfig.attributes(security: 'wep') }, 'Security'
      assert_includes refused { WlanConfig.attributes(pmf: 'maybe') }, 'PMF'
      assert_includes refused { WlanConfig.attributes(band: '7g') }, 'Band'
      assert_includes refused { WlanConfig.attributes(name: '') }, 'SSID'
      assert_includes refused { WlanConfig.attributes(name: 'x' * 33) }, 'SSID'
    end

    def test_describe_never_echoes_the_passphrase
      lines = WlanConfig.describe(WlanConfig.attributes(passphrase: 'correct horse battery', band: 'all', guest: true))

      refute_includes lines.join, 'correct horse'
      assert_includes lines, 'passphrase: updated'
      assert_includes lines, 'band: 2g+5g+6g'
      assert_includes lines, 'is_guest: true'
    end

    private

    def refused
      assert_raises(WlanConfig::Invalid) { yield }.message
    end
  end
end
