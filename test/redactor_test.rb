require_relative 'test_helper'

module UiManage
  class RedactorTest < TestCase
    def test_unifi_x_prefixed_fields_are_redacted
      scrubbed = Redactor.scrub('x_passphrase' => 'correct horse battery staple')

      assert_equal Redactor::PLACEHOLDER, scrubbed['x_passphrase']
    end

    def test_plainly_named_credentials_are_redacted
      scrubbed = Redactor.scrub(
        'password'    => 'pw',
        'x_secret'    => 's',
        'api_key'     => 'k',
        'community'   => 'public',
        'private_key' => 'pk'
      )

      scrubbed.each_value { |v| assert_equal Redactor::PLACEHOLDER, v }
    end

    def test_ordinary_fields_are_untouched
      scrubbed = Redactor.scrub('name' => 'Guest', 'vlan' => 30, 'enabled' => true)

      assert_equal({ 'name' => 'Guest', 'vlan' => 30, 'enabled' => true }, scrubbed)
    end

    # "no SSH password is set" is itself a finding, so an unset value must not
    # become indistinguishable from a set one.
    def test_an_unset_secret_stays_visibly_unset
      scrubbed = Redactor.scrub('x_ssh_password' => '', 'x_secret' => nil, 'x_enabled' => false)

      assert_equal '',  scrubbed['x_ssh_password']
      assert_nil        scrubbed['x_secret']
      assert_equal false, scrubbed['x_enabled']
    end

    def test_nested_structures_are_scrubbed_throughout
      scrubbed = Redactor.scrub(
        'networks' => [{ 'name' => 'vpn', 'x_ipsec_pre_shared_key' => 'psk' }],
        'nested'   => { 'deep' => { 'passphrase' => 'p' } }
      )

      assert_equal Redactor::PLACEHOLDER, scrubbed['networks'][0]['x_ipsec_pre_shared_key']
      assert_equal 'vpn', scrubbed['networks'][0]['name']
      assert_equal Redactor::PLACEHOLDER, scrubbed['nested']['deep']['passphrase']
    end

    def test_scrubbing_does_not_mutate_the_original
      original = { 'x_passphrase' => 'secret' }
      Redactor.scrub(original)

      assert_equal 'secret', original['x_passphrase']
    end

    # Redaction lives in Formatter.json so a new command cannot forget it.
    def test_json_output_is_redacted_at_the_render_boundary
      out, = capture_io { Formatter.json([{ 'name' => 'IoT', 'x_passphrase' => 'hunter2' }]) }

      refute_includes out, 'hunter2'
      assert_includes out, Redactor::PLACEHOLDER
      assert_includes out, 'IoT'
    end
  end
end
