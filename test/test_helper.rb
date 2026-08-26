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

    # Answers each request from +routes+, keyed by a fragment of the endpoint
    # path. A value that is an Integer is served as that HTTP status, which is
    # how a test makes an endpoint unavailable; anything else is served as a
    # successful payload. Unlisted paths answer with an empty list.
    def stub_transport(routes = {})
      FakeTransport.new do |req|
        key = routes.keys.find { |k| req.path.include?(k.to_s) }
        value = key ? routes[key] : []
        value.is_a?(Integer) ? FakeTransport.status(value) : FakeTransport.ok(value)
      end
    end

    # Runs a CLI command against a stubbed controller and returns what it
    # printed. Options are the command's own flags.
    # A braceless trailing hash is captured as keywords under Ruby 3, and
    # keywords may have String keys — so `render(:wlans, 'wlanconf' => [...])`
    # would otherwise arrive as an option rather than a route, or as an
    # "unknown keyword" error. Endpoint routes are the String-keyed entries;
    # flags and settings are the Symbol-keyed ones.
    def split_routes(routes, options)
      [routes.merge(options.select { |k, _| k.is_a?(String) }),
       options.reject { |k, _| k.is_a?(String) }]
    end

    def render(command, routes = {}, **options)
      routes, options = split_routes(routes, options)

      transport = stub_transport(routes)
      client    = Client.new(host: 'unifi.test', api_key: 'test-key', transport: transport)
      shell     = CLI.new([], Thor::CoreExt::HashWithIndifferentAccess.new(options))
      shell.define_singleton_method(:resolve_client) { client }

      out, = capture_io { shell.public_send(command) }
      out
    end

    def assert_aborts(message_fragment)
      err = capture_io { assert_raises(SystemExit) { yield } }
      assert_includes err.join, message_fragment
    end
  end
end
