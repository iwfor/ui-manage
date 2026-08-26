require_relative 'test_helper'

module UiManage
  class ClientTest < TestCase
    SITE_PREFIX = '/proxy/network/api/s/default'.freeze

    def test_requires_some_credential
      assert_raises(ArgumentError) { Client.new(host: 'unifi.test') }
      assert_raises(ArgumentError) { Client.new(host: 'unifi.test', username: 'admin') }
    end

    # --- endpoint table -------------------------------------------------------

    def test_every_declared_network_endpoint_hits_its_site_scoped_path
      Client::NETWORK_ENDPOINTS.each do |name, path|
        transport = FakeTransport.new { FakeTransport.ok([{ 'x' => 1 }]) }
        client    = build_client(transport)

        assert_equal [{ 'x' => 1 }], client.public_send(name), "#{name} returned the wrong payload"
        assert_equal "#{SITE_PREFIX}#{path}", transport.paths.first, "#{name} used the wrong path"
        assert_equal :get, transport.requests.first.method
      end
    end

    def test_site_name_is_used_in_the_path
      transport = FakeTransport.new { FakeTransport.ok }
      build_client(transport, site: 'office').devices

      assert_equal '/proxy/network/api/s/office/stat/device', transport.paths.first
    end

    def test_os_endpoints_bypass_the_network_proxy_and_have_no_envelope
      payload   = { 'name' => 'Dream Machine', 'version' => '4.0.6' }
      transport = FakeTransport.new { FakeTransport.bare(payload) }

      assert_equal payload, build_client(transport).os_system
      assert_equal '/api/system', transport.paths.first
    end

    def test_optional_endpoints_cover_everything_outside_the_core_set
      declared = Client::NETWORK_ENDPOINTS.keys + Client::OS_ENDPOINTS.keys
      expected = declared - Client::CORE_ENDPOINTS

      expected.each do |name|
        assert_includes Client::OPTIONAL_ENDPOINTS, name, "#{name} should be optional"
      end
      Client::CORE_ENDPOINTS.each do |name|
        refute_includes Client::OPTIONAL_ENDPOINTS, name, "#{name} should not be optional"
      end
    end

    # --- query parameters -----------------------------------------------------

    def test_alarms_passes_window_and_archive_filter_as_query_params
      transport = FakeTransport.new { FakeTransport.ok }
      build_client(transport).alarms(within: 72)

      assert_equal({ 'within' => '72', 'archived' => 'false' }, transport.requests.first.query)
    end

    def test_events_and_ips_events_pass_a_limit
      transport = FakeTransport.new { FakeTransport.ok }
      client    = build_client(transport)
      client.events(within: 12, limit: 50)
      client.ips_events(within: 12, limit: 50)

      assert_equal({ 'within' => '12', '_limit' => '50' }, transport.requests[0].query)
      assert_equal "#{SITE_PREFIX}/stat/ips/event", transport.paths[1]
    end

    def test_admins_posts_the_sitemgr_command
      transport = FakeTransport.new { FakeTransport.ok([{ 'name' => 'admin' }]) }
      build_client(transport).admins
      req = transport.requests.first

      assert_equal :post, req.method
      assert_equal "#{SITE_PREFIX}/cmd/sitemgr", req.path
      assert_equal({ 'cmd' => 'get-admins' }, req.json_body)
    end

    def test_site_stats_posts_a_bounded_time_range
      transport = FakeTransport.new { FakeTransport.ok }
      build_client(transport).site_stats(days: 2)
      body = transport.requests.first.json_body

      assert_operator body['end'], :>, body['start']
      assert_in_delta 2 * 24 * 60 * 60 * 1000, body['end'] - body['start'], 1000
      assert_includes body['attrs'], 'time'
    end

    # --- caching --------------------------------------------------------------

    def test_repeated_reads_hit_the_controller_once
      transport = FakeTransport.new { FakeTransport.ok }
      client    = build_client(transport)
      3.times { client.devices }

      assert_equal 1, transport.requests.size
    end

    def test_cache_is_keyed_by_arguments
      transport = FakeTransport.new { FakeTransport.ok }
      client    = build_client(transport)
      client.alarms(within: 24)
      client.alarms(within: 24)
      client.alarms(within: 48)

      assert_equal 2, transport.requests.size
    end

    def test_clear_cache_forces_a_refetch
      transport = FakeTransport.new { FakeTransport.ok }
      client    = build_client(transport)
      client.devices
      client.clear_cache!
      client.devices

      assert_equal 2, transport.requests.size
    end

    def test_a_write_invalidates_the_cache
      transport = FakeTransport.new { FakeTransport.ok }
      client    = build_client(transport)
      client.devices
      client.set_port_poe(device: { '_id' => 'abc', 'port_overrides' => [] }, port_idx: 1, enabled: true)
      client.devices

      assert_equal 3, transport.requests.size
      assert_equal :put, transport.requests[1].method
    end

    # --- degradation ----------------------------------------------------------

    def test_optional_returns_nil_and_records_a_reason_when_forbidden
      transport = FakeTransport.new { FakeTransport.status(403) }
      client    = build_client(transport)

      assert_nil client.optional(:admins)
      assert client.degraded?(:admins)
      assert_includes client.degradations[:admins], 'not permitted'
    end

    def test_optional_records_a_version_hint_for_a_missing_endpoint
      transport = FakeTransport.new { FakeTransport.status(404) }
      client    = build_client(transport)

      assert_nil client.optional(:ips_events)
      assert_includes client.degradations[:ips_events], 'does not provide it'
    end

    def test_a_degraded_endpoint_is_not_retried
      transport = FakeTransport.new { FakeTransport.status(403) }
      client    = build_client(transport)
      3.times { client.optional(:wlans) }

      assert_equal 1, transport.requests.size
    end

    def test_optional_treats_a_permission_error_in_the_envelope_as_unavailable
      transport = FakeTransport.new { FakeTransport.api_error('api.err.NoPermission') }
      client    = build_client(transport)

      assert_nil client.optional(:settings)
      assert_includes client.degradations[:settings], 'api.err.NoPermission'
    end

    def test_optional_does_not_swallow_a_genuine_api_error
      transport = FakeTransport.new { FakeTransport.api_error('api.err.InvalidPayload') }
      client    = build_client(transport)

      error = assert_raises(Client::ApiError) { client.optional(:settings) }
      assert_includes error.message, 'api.err.InvalidPayload'
      refute client.degraded?(:settings)
    end

    def test_optional_rejects_an_endpoint_that_is_not_optional
      client = build_client(FakeTransport.new { FakeTransport.ok })

      assert_raises(ArgumentError) { client.optional(:devices) }
    end

    def test_core_endpoints_still_raise_rather_than_degrade
      transport = FakeTransport.new { FakeTransport.status(403) }
      client    = build_client(transport)

      error = assert_raises(Client::EndpointUnavailable) { client.devices }
      assert_equal 403, error.status
      assert_equal '/stat/device', error.endpoint
      assert_empty client.degradations
    end

    def test_degradations_are_a_copy
      transport = FakeTransport.new { FakeTransport.status(403) }
      client    = build_client(transport)
      client.optional(:admins)
      client.degradations[:admins] = 'tampered'

      refute_equal 'tampered', client.degradations[:admins]
    end

    # --- errors ---------------------------------------------------------------

    def test_a_server_error_is_reported_with_its_status
      transport = FakeTransport.new { FakeTransport.status(500, 'boom') }
      client    = build_client(transport)

      error = assert_raises(Client::ApiError) { client.devices }
      assert_includes error.message, '500'
    end

    def test_unparseable_json_names_the_endpoint
      transport = FakeTransport.new { FakeTransport.status(200, '<html>login</html>') }
      client    = build_client(transport)

      error = assert_raises(Client::ApiError) { client.devices }
      assert_includes error.message, '/stat/device'
    end

    def test_transport_failure_surfaces_as_an_api_error
      transport = FakeTransport.new { raise CurlTransport::TransportError, 'curl not found in PATH' }
      client    = build_client(transport)

      error = assert_raises(Client::ApiError) { client.devices }
      assert_includes error.message, 'curl not found'
    end

    # --- authentication -------------------------------------------------------

    def test_api_key_is_sent_as_a_secret_header
      transport = FakeTransport.new { FakeTransport.ok }
      build_client(transport, api_key: 'sekrit').devices
      req = transport.requests.first

      assert_equal 'sekrit', req.header('X-API-Key')
      assert_includes req.secret_headers, 'X-API-Key'
    end

    def test_session_auth_logs_in_once_then_reuses_the_token
      transport = FakeTransport.new do |req|
        req.path == '/api/auth/login' ? FakeTransport.login_ok : FakeTransport.ok
      end
      client = build_client(transport, username: 'admin', password: 'pw')
      client.devices
      client.clear_cache!
      client.devices

      assert_equal 1, transport.paths.count('/api/auth/login')
      assert_equal 'TOKEN=session-token', transport.requests.last.header('Cookie')
      assert_equal 'csrf-token', transport.requests.last.header('X-Csrf-Token')
    end

    def test_session_and_csrf_headers_are_marked_secret
      transport = FakeTransport.new do |req|
        req.path == '/api/auth/login' ? FakeTransport.login_ok : FakeTransport.ok
      end
      build_client(transport, username: 'admin', password: 'pw').devices

      assert_equal %w[Cookie X-Csrf-Token], transport.requests.last.secret_headers
    end

    def test_an_expired_session_is_renewed_once_and_the_request_retried
      calls = Hash.new(0)
      transport = FakeTransport.new do |req|
        calls[req.path] += 1
        if req.path == '/api/auth/login'
          FakeTransport.login_ok(token: "token-#{calls[req.path]}")
        elsif calls[req.path] == 1
          FakeTransport.status(401)
        else
          FakeTransport.ok([{ 'name' => 'switch' }])
        end
      end
      client = build_client(transport, username: 'admin', password: 'pw')

      assert_equal [{ 'name' => 'switch' }], client.devices
      assert_equal 2, transport.paths.count('/api/auth/login')
      assert_equal 'TOKEN=token-2', transport.requests.last.header('Cookie')
    end

    def test_a_persistent_401_is_reported_rather_than_looping
      transport = FakeTransport.new do |req|
        req.path == '/api/auth/login' ? FakeTransport.login_ok : FakeTransport.status(401)
      end
      client = build_client(transport, username: 'admin', password: 'pw')

      assert_raises(Client::EndpointUnavailable) { client.devices }
      assert_equal 2, transport.paths.count('/api/auth/login')
    end

    def test_an_api_key_session_is_never_re_logged_in
      transport = FakeTransport.new { FakeTransport.status(401) }
      client    = build_client(transport, api_key: 'sekrit')

      assert_raises(Client::EndpointUnavailable) { client.devices }
      refute_includes transport.paths, '/api/auth/login'
    end

    def test_a_rejected_login_reports_an_auth_error
      transport = FakeTransport.new { FakeTransport.api_error('api.err.Invalid', status: 400) }
      client    = build_client(transport, username: 'admin', password: 'wrong')

      error = assert_raises(Client::AuthError) { client.login }
      assert_includes error.message, 'api.err.Invalid'
    end

    def test_a_login_without_a_token_is_an_auth_error
      transport = FakeTransport.new { FakeTransport.ok }
      client    = build_client(transport, username: 'admin', password: 'pw')

      assert_raises(Client::AuthError) { client.login }
    end

    def test_login_falls_back_to_the_csrf_token_in_the_body
      transport = FakeTransport.new do
        CurlTransport::Response.new(
          status:  200,
          headers: ['HTTP/1.1 200 OK', 'Set-Cookie: TOKEN=abc; Path=/'],
          body:    JSON.generate('meta' => { 'rc' => 'ok' }, 'data' => { 'csrf_token' => 'from-body' })
        )
      end
      client = build_client(transport, username: 'admin', password: 'pw')
      client.login
      client.devices

      assert_equal 'from-body', transport.requests.last.header('X-Csrf-Token')
    end

    # --- URLs -----------------------------------------------------------------

    def test_a_bare_host_is_addressed_over_https
      transport = FakeTransport.new { FakeTransport.ok }
      build_client(transport, host: '192.168.1.1').devices

      assert transport.requests.first.url.start_with?('https://192.168.1.1/')
    end

    def test_an_explicit_scheme_and_port_are_preserved
      transport = FakeTransport.new { FakeTransport.ok }
      build_client(transport, host: 'http://unifi.test:8443').devices

      assert transport.requests.first.url.start_with?('http://unifi.test:8443/')
    end

    # --- behaviour ------------------------------------------------------------

    def test_gateway_device_prefers_the_udm
      devices = [{ 'type' => 'usw' }, { 'type' => 'udm', 'name' => 'gw' }]
      client  = build_client(FakeTransport.new { FakeTransport.ok(devices) })

      assert_equal 'gw', client.gateway_device['name']
    end

    def test_gateway_device_falls_back_to_a_device_reporting_system_stats
      devices = [{ 'type' => 'usw' }, { 'type' => 'uap', 'sys_stats' => {}, 'name' => 'ap' }]
      client  = build_client(FakeTransport.new { FakeTransport.ok(devices) })

      assert_equal 'ap', client.gateway_device['name']
    end

    def test_setting_poe_preserves_other_port_overrides
      transport = FakeTransport.new { FakeTransport.ok }
      device    = { '_id' => 'dev1',
                    'port_overrides' => [{ 'port_idx' => 1, 'poe_mode' => 'auto' },
                                         { 'port_idx' => 2, 'name' => 'uplink' }] }
      build_client(transport).set_port_poe(device: device, port_idx: 2, enabled: false)
      overrides = transport.requests.first.json_body['port_overrides']

      assert_equal 'auto', overrides.find { |o| o['port_idx'] == 1 }['poe_mode']
      assert_equal 'off',  overrides.find { |o| o['port_idx'] == 2 }['poe_mode']
      assert_equal 'uplink', overrides.find { |o| o['port_idx'] == 2 }['name']
    end

    def test_setting_poe_on_an_unlisted_port_adds_an_override
      transport = FakeTransport.new { FakeTransport.ok }
      device    = { '_id' => 'dev1', 'port_overrides' => [] }
      build_client(transport).set_port_poe(device: device, port_idx: 5, enabled: true)

      assert_equal [{ 'port_idx' => 5, 'poe_mode' => 'auto' }],
                   transport.requests.first.json_body['port_overrides']
    end

    def test_setting_poe_does_not_mutate_the_caller_s_device
      transport = FakeTransport.new { FakeTransport.ok }
      device    = { '_id' => 'dev1', 'port_overrides' => [{ 'port_idx' => 1, 'poe_mode' => 'auto' }] }
      build_client(transport).set_port_poe(device: device, port_idx: 1, enabled: false)

      assert_equal 'auto', device['port_overrides'].first['poe_mode']
    end
  end
end
