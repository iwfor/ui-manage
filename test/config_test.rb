require_relative 'test_helper'

module UiManage
  class ConfigTest < TestCase
    def add(name: 'udm', **args)
      config = Config.new
      config.add_device(name: name, host: '192.168.1.1', username: 'admin',
                        encrypted_password: 'cipher', **args)
      config
    end

    def stored(name = 'udm')
      Config.new.device(name)
    end

    # --- remote access policy -------------------------------------------------

    def test_a_device_can_record_that_remote_access_is_expected
      add(remote_access_expected: true)

      assert_equal true, stored['remote_access_expected']
    end

    def test_a_device_can_record_that_remote_access_is_not_expected
      add(remote_access_expected: false)

      assert_equal false, stored['remote_access_expected']
    end

    def test_an_unanswered_policy_question_leaves_the_setting_unconfigured
      add

      refute stored.key?('remote_access_expected')
    end

    def test_re_adding_a_device_without_an_answer_keeps_the_existing_policy
      add(remote_access_expected: true)
      add # e.g. re-running login to rotate a credential

      assert_equal true, stored['remote_access_expected']
    end

    def test_re_adding_a_device_with_an_answer_replaces_the_existing_policy
      add(remote_access_expected: true)
      add(remote_access_expected: false)

      assert_equal false, stored['remote_access_expected']
    end

    def test_the_policy_survives_a_write_and_reread
      add(remote_access_expected: true)
      raw = File.read(Config::CONFIG_FILE)

      assert_includes raw, 'remote_access_expected'
      assert_equal true, stored['remote_access_expected']
    end

    # --- policy updates -------------------------------------------------------

    def test_policy_can_be_set_on_an_existing_device
      add
      Config.new.update_device_policy('udm', remote_access_expected: true)

      assert_equal true, stored['remote_access_expected']
    end

    def test_policy_can_be_cleared
      add(remote_access_expected: true)
      Config.new.update_device_policy('udm', remote_access_expected: nil)

      refute stored.key?('remote_access_expected')
    end

    def test_clearing_policy_leaves_the_rest_of_the_device_intact
      add(remote_access_expected: true)
      Config.new.update_device_policy('udm', remote_access_expected: nil)

      assert_equal 'admin',  stored['username']
      assert_equal 'cipher', stored['encrypted_password']
      assert_equal '192.168.1.1', stored['host']
    end

    def test_policy_values_are_coerced_to_booleans
      add
      Config.new.update_device_policy('udm', remote_access_expected: 'yes')

      assert_equal true, stored['remote_access_expected']
    end

    def test_only_policy_keys_may_be_updated_this_way
      add
      config = Config.new

      error = assert_raises(ArgumentError) { config.update_device_policy('udm', host: 'evil.test') }
      assert_includes error.message, 'host'
      assert_equal '192.168.1.1', stored['host']
    end

    def test_updating_policy_on_an_unknown_device_raises
      add

      assert_raises(RuntimeError) { Config.new.update_device_policy('nope', remote_access_expected: true) }
    end

    # --- existing behaviour, previously untested ------------------------------

    def test_the_first_device_added_becomes_the_default
      add(name: 'first')
      add(name: 'second')

      assert_equal 'first', Config.new.default_device_name
    end

    def test_an_api_key_device_stores_no_username_or_password
      Config.new.add_device(name: 'key', host: '10.0.0.1', encrypted_api_key: 'cipher')
      dev = stored('key')

      assert_equal 'cipher', dev['encrypted_api_key']
      refute dev.key?('username')
      refute dev.key?('encrypted_password')
    end

    def test_removing_the_default_device_promotes_another
      add(name: 'first')
      add(name: 'second')
      Config.new.remove_device('first')

      assert_equal 'second', Config.new.default_device_name
    end

    def test_control_characters_are_rejected_so_the_config_stays_readable
      config = Config.new

      assert_raises(ArgumentError) do
        config.add_device(name: "bad\nname", host: '10.0.0.1', encrypted_api_key: 'c')
      end
    end

    def test_the_config_file_is_not_readable_by_anyone_else
      add

      assert_equal '600', format('%o', File.stat(Config::CONFIG_FILE).mode & 0o777)
    end

    def test_an_unknown_device_name_is_reported
      add

      error = assert_raises(RuntimeError) { Config.new.device('missing') }
      assert_includes error.message, 'missing'
    end
  end
end
