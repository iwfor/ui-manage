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

    # --- system log -------------------------------------------------------------

    SYSTEM_LOG = '/proxy/network/v2/api/site/default/system-log/all'.freeze

    # The v2 endpoint answers {data, page_number, ...} with no meta block.
    def system_log_page(entries)
      FakeTransport.bare({ 'data' => entries, 'page_number' => 0, 'total_page_count' => 1 })
    end

    def test_events_read_one_page_of_the_system_log_over_the_window
      transport = FakeTransport.new { system_log_page([{ 'key' => 'X' }]) }
      before    = (Time.now.to_f * 1000).to_i

      assert_equal [{ 'key' => 'X' }], build_client(transport).events(within: 12, limit: 50)

      req = transport.requests.first
      assert_equal :post, req.method
      assert_equal SYSTEM_LOG, req.path
      body = req.json_body
      assert_equal 0,  body['pageNumber']
      assert_equal 50, body['pageSize']
      assert_in_delta 12 * 60 * 60 * 1000, body['timestampTo'] - body['timestampFrom'], 1000
      assert_operator body['timestampTo'], :>=, before
      refute body.key?('categories')
      refute body.key?('severities')
    end

    def test_threats_are_the_security_category_and_alarms_the_severe_entries
      transport = FakeTransport.new { system_log_page([]) }
      client    = build_client(transport)
      client.ips_events
      client.alarms

      assert_equal ['SECURITY'], transport.requests[0].json_body['categories']
      assert_equal %w[WARNING HIGH VERY_HIGH], transport.requests[1].json_body['severities']
    end

    def test_archived_alarms_are_left_out_unless_asked_for
      entries   = [{ 'key' => 'live', 'status' => 'NEW' }, { 'key' => 'old', 'status' => 'ARCHIVED' }]
      transport = FakeTransport.new { system_log_page(entries) }
      client    = build_client(transport)

      assert_equal ['live'], client.alarms.map { |e| e['key'] }
      assert_equal %w[live old], client.alarms(archived: true).map { |e| e['key'] }
    end

    def test_the_system_log_is_cached_on_its_arguments_not_the_time_of_the_call
      transport = FakeTransport.new { system_log_page([]) }
      client    = build_client(transport)
      client.events(within: 24)
      client.events(within: 24)
      client.events(within: 48)

      assert_equal 2, transport.requests.size
    end

    # A controller from before the system log existed still has the endpoints
    # it replaced.
    def test_an_older_controller_falls_back_to_the_legacy_endpoints
      transport = FakeTransport.new do |req|
        req.path == SYSTEM_LOG ? FakeTransport.status(404) : FakeTransport.ok([{ 'key' => 'legacy' }])
      end
      client = build_client(transport)

      assert_equal [{ 'key' => 'legacy' }], client.alarms(within: 72)
      assert_equal "#{SITE_PREFIX}/stat/alarm", transport.paths.last
      assert_equal({ 'within' => '72', 'archived' => 'false' }, transport.requests.last.query)

      client.events(within: 12, limit: 50)
      assert_equal({ 'within' => '12', '_limit' => '50' }, transport.requests.last.query)

      client.ips_events
      assert_equal "#{SITE_PREFIX}/stat/ips/event", transport.paths.last
    end

    def test_when_neither_the_system_log_nor_the_legacy_endpoint_answers_both_are_named
      transport = FakeTransport.new { FakeTransport.status(404) }
      error     = assert_raises(Client::EndpointUnavailable) { build_client(transport).events }

      assert_includes error.message, '/system-log/all'
      assert_includes error.message, '/stat/event'
    end

    # --- administrators -------------------------------------------------------

    def test_admins_are_read_controller_wide_and_narrowed_to_this_site
      admins = [
        { 'name' => 'root',  'is_super' => true },
        { 'name' => 'here',  'roles' => [{ 'site_name' => 'default', 'role' => 'admin' }] },
        { 'name' => 'there', 'roles' => [{ 'site_name' => 'branch', 'role' => 'admin' }] },
        { 'name' => 'bare' }
      ]
      transport = FakeTransport.new { FakeTransport.ok(admins) }
      req_names = build_client(transport).admins.map { |a| a['name'] }

      assert_equal %w[root here bare], req_names
      assert_equal :get, transport.requests.first.method
      assert_equal '/proxy/network/api/stat/admin', transport.paths.first
    end

    def test_os_users_come_from_the_console_user_service_unwrapped
      transport = FakeTransport.new { FakeTransport.bare({ 'code' => 1, 'data' => [{ 'full_name' => 'Op' }] }) }

      assert_equal [{ 'full_name' => 'Op' }], build_client(transport).os_users
      assert_equal '/proxy/users/api/v2/users', transport.paths.first
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

    def test_a_v2_error_reports_the_message_field
      transport = FakeTransport.new { FakeTransport.bare({ 'errorCode' => 400, 'message' => 'bad filter' }, status: 400) }
      client    = build_client(transport)

      error = assert_raises(Client::ApiError) { client.events }
      assert_includes error.message, 'bad filter'
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

# --- writes ---------------------------------------------------------------

def test_create_network_posts_and_returns_the_stored_record
  transport = FakeTransport.new { FakeTransport.ok([{ "_id" => "n1", "name" => "IoT" }]) }
  net = build_client(transport).create_network("name" => "IoT")

  assert_equal "n1", net["_id"]
  assert_equal :post, transport.requests.first.method
  assert_equal "/proxy/network/api/s/default/rest/networkconf", transport.requests.first.path
  assert_equal({ "name" => "IoT" }, transport.requests.first.json_body)
end

def test_update_and_delete_hit_the_record_by_id_and_drop_the_cache
  transport = FakeTransport.new { FakeTransport.ok([]) }
  client    = build_client(transport)
  client.networks
  client.update_network("n1", "name" => "Renamed")
  client.networks
  client.delete_network("n1")
  client.networks

  methods = transport.requests.map { |r| [r.method, r.path.split("/").last(2).join("/")] }
  assert_equal [[:get, "rest/networkconf"], [:put, "networkconf/n1"], [:get, "rest/networkconf"],
                [:delete, "networkconf/n1"], [:get, "rest/networkconf"]], methods
end

def test_wlan_and_known_client_updates_are_partial_puts
  transport = FakeTransport.new { FakeTransport.ok([]) }
  client    = build_client(transport)
  client.update_wlan("w1", "is_guest" => true)
  client.update_known_client("u1", "virtual_network_override_enabled" => true)

  assert_equal "/proxy/network/api/s/default/rest/wlanconf/w1", transport.requests[0].path
  assert_equal({ "is_guest" => true }, transport.requests[0].json_body)
  assert_equal "/proxy/network/api/s/default/rest/user/u1", transport.requests[1].path
  assert_equal :put, transport.requests[1].method
end

def test_firewall_zones_read_the_v2_endpoint_and_are_optional
  transport = FakeTransport.new { |req| req.path.include?("firewall/zone") ? FakeTransport.ok([{ "zone_key" => "hotspot" }]) : FakeTransport.status(404) }
  client    = build_client(transport)

  assert_equal "hotspot", client.firewall_zones.first["zone_key"]
  assert_equal "/proxy/network/v2/api/site/default/firewall/zone", transport.requests.first.path
  assert_nil build_client(FakeTransport.new { FakeTransport.status(404) }).optional(:firewall_zones)
end
  end
end
