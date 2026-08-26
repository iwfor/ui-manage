require 'tmpdir'
require 'fileutils'

# Point the config directory at a throwaway location *before* loading the
# library — CONFIG_DIR, CONFIG_FILE, and KEY_FILE are constants resolved at
# require time, and a test run must never touch the real ~/.config/ui-manage.
TEST_CONFIG_DIR = Dir.mktmpdir('ui-manage-test')
ENV['UI_MANAGE_CONFIG_DIR'] = TEST_CONFIG_DIR

require 'minitest/autorun'
Minitest.after_run { FileUtils.remove_entry(TEST_CONFIG_DIR, true) }

$LOAD_PATH.unshift File.expand_path('../lib', __dir__)
require 'ui_manage'

require_relative 'support/fake_transport'

module UiManage
  class TestCase < Minitest::Test
    def setup
      FileUtils.rm_f(Config::CONFIG_FILE)
    end

    # Builds a Client wired to a FakeTransport. Defaults to API-key auth so a
    # test does not have to service a login round-trip it isn't interested in.
    def build_client(transport, host: 'unifi.test', site: 'default', **args)
      args = { api_key: 'test-key' } if args.empty?
      Client.new(host: host, site: site, transport: transport, **args)
    end

    def assert_aborts(message_fragment)
      err = capture_io { assert_raises(SystemExit) { yield } }
      assert_includes err.join, message_fragment
    end
  end
end
