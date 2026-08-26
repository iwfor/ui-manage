require_relative '../test_helper'

module UiManage
  module Audit
    class ContextTest < TestCase
      def build(routes = {}, **options)
        routes, options = split_routes(routes, options)
        device    = options.fetch(:device, {})
        transport = stub_transport(routes)
        client    = Client.new(host: 'unifi.test', api_key: 'k', transport: transport)
        [Context.new(client: client, device: device, settings: Settings.new(path: nil)), transport]
      end

      # An audit reads the same endpoints from many independent checks; the
      # controller should see one request per endpoint for the whole run.
      def test_an_endpoint_is_fetched_once_however_many_checks_read_it
        context, transport = build('stat/device' => [{ 'name' => 'AP' }])
        5.times { context.data(:devices) }

        assert_equal 1, transport.requests.size
      end

      def test_a_refused_endpoint_is_not_retried_by_later_checks
        context, transport = build('wlanconf' => 403)
        5.times { context.data(:wlans) }

        assert_equal 1, transport.requests.size
      end

      def test_an_available_endpoint_reports_available
        context, = build('stat/device' => [{ 'name' => 'AP' }])

        assert context.available?(:devices)
        assert_nil context.unavailable_reason(:devices)
      end

      # An endpoint that legitimately has nothing to report is available —
      # only nil means the controller would not serve it.
      def test_an_empty_response_is_still_available
        context, = build('wlanconf' => [])

        assert context.available?(:wlans)
        assert_equal [], context.data(:wlans)
      end

      def test_a_refused_endpoint_reports_why
        context, = build('wlanconf' => 403)

        refute context.available?(:wlans)
        assert_includes context.unavailable_reason(:wlans), 'not permitted'
      end

      # A core endpoint can be refused too — a credential scoped to one site,
      # say — and that must degrade rather than end the audit.
      def test_a_refused_core_endpoint_degrades_rather_than_raising
        context, = build('stat/device' => 403)

        refute context.available?(:devices)
        assert_includes context.unavailable_reason(:devices), 'not permitted'
      end

      def test_a_named_settings_section_is_found_by_key
        context, = build('get/setting' => [{ 'key' => 'mgmt', 'x_ssh_enabled' => true },
                                           { 'key' => 'ips', 'enabled' => false }])

        assert_equal true, context.setting('mgmt')['x_ssh_enabled']
        assert_nil context.setting('nonexistent')
      end

      def test_settings_lookup_is_nil_when_the_endpoint_is_refused
        context, = build('get/setting' => 403)

        assert_nil context.setting('mgmt')
      end

      def test_device_policy_is_readable_by_checks
        context, = build({}, device: { 'remote_access_expected' => true })

        assert_equal true, context.policy(:remote_access_expected)
        assert_nil context.policy(:never_set)
      end

      def test_thresholds_come_from_the_settings
        context, = build

        assert_equal 80, context.threshold('cpu_percent')
      end
    end
  end
end
