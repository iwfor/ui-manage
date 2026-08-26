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

    # A braceless trailing hash is captured as keywords under Ruby 3, and
    # keywords may have String keys — so `render(:wlans, 'wlanconf' => [...])` would
    # otherwise arrive as an option rather than a route, or as an "unknown
    # keyword" error. Endpoint routes are the String-keyed entries; flags and
    # settings are the Symbol-keyed ones.
    def split_routes(routes, options)
      [routes.merge(options.select { |k, _| k.is_a?(String) }),
       options.reject { |k, _| k.is_a?(String) }]
    end

    # Builds a CLI instance wired to a stubbed controller.
    def cli_for(command, routes, options)
      device    = options.delete(:device_config) || {}
      transport = stub_transport(routes)
      client    = Client.new(host: 'unifi.test', api_key: 'test-key', transport: transport)
      shell     = CLI.new([], Thor::CoreExt::HashWithIndifferentAccess.new(
        option_defaults(command).merge(options)
      ))
      shell.define_singleton_method(:resolve_client) { client }
      # Views that reach the audit need the device entry too, for its policy.
      shell.define_singleton_method(:resolve_device) { device }
      shell
    end

    # Thor applies option defaults while parsing argv. Constructing a command
    # directly skips that, so a test would see nil where a real invocation sees
    # the declared default — applied here so the two behave the same.
    def option_defaults(command)
      declared = CLI.commands[command.to_s]&.options || {}
      declared.merge(CLI.class_options)
              .filter_map { |name, option| [name, option.default] unless option.default.nil? }
              .to_h
    end

    # Invokes a command without capturing its output, so a caller can wrap it
    # in its own capture — assert_aborts does, and nesting captures would
    # swallow the message it is looking for.
    def invoke(command, routes = {}, args: [], **options)
      routes, options = split_routes(routes, options)
      cli_for(command, routes, options).public_send(command, *args)
    end

    # Runs a CLI command against a stubbed controller and returns what it
    # printed. Options are the command's own flags; `args:` are its positional
    # arguments.
    def render(command, routes = {}, args: [], **options)
      routes, options = split_routes(routes, options)
      shell = cli_for(command, routes, options)
      out, = capture_io { shell.public_send(command, *args) }
      out
    end

    # Like #render, for commands that exit. Returns [output, exit status].
    def render_with_status(command, routes = {}, args: [], **options)
      routes, options = split_routes(routes, options)
      shell  = cli_for(command, routes, options)
      status = 0
      out, = capture_io do
        begin
          shell.public_send(command, *args)
        rescue SystemExit => e
          status = e.status
        end
      end
      [out, status]
    end

    # Runs one audit check against a stubbed controller and returns its Report.
    # `device:` supplies the audit policy, `settings:` the thresholds.
    def audit_report(id, routes = {}, **options)
      routes, options = split_routes(routes, options)
      client  = Client.new(host: 'unifi.test', api_key: 'k', transport: stub_transport(routes))
      context = Audit::Context.new(
        client:   client,
        device:   options.fetch(:device, {}),
        settings: options[:settings] || Audit::Settings.new(path: nil)
      )
      check = Audit::Registry.find(id) or raise "No such check: #{id}"
      Audit::Runner.new(context: context, checks: [check]).run
    end

    def assert_aborts(message_fragment)
      err = capture_io { assert_raises(SystemExit) { yield } }
      assert_includes err.join, message_fragment
    end
  end
end
