require 'json'
require 'uri'

module UiManage
  class Client
    class ApiError  < StandardError; end
    class AuthError < StandardError; end

    # Raised when the controller refuses or does not implement an endpoint:
    # a credential without the necessary privilege (reading the administrator
    # list, say), or a Network application too old to expose it. Audit
    # checks that depend on such an endpoint degrade to a "skipped" result
    # rather than failing the whole run — see #optional.
    class EndpointUnavailable < ApiError
      attr_reader :endpoint, :status

      def initialize(message, endpoint:, status: nil)
        super(message)
        @endpoint = endpoint
        @status   = status
      end
    end

    NETWORK_PREFIX = '/proxy/network/api/s'

    # The Network application's newer API, which is where the system log
    # (events, alarms, IDS/IPS detections) moved in version 9.
    V2_PREFIX = '/proxy/network/v2/api/site'

    # HTTP statuses that mean "this credential or controller can't give you
    # this endpoint" rather than "the request was wrong".
    UNAVAILABLE_STATUSES = [401, 403, 404, 405, 501].freeze

    # Controller-level error codes carrying the same meaning.
    UNAVAILABLE_ERRORS = %w[api.err.NoPermission api.err.NoSiteContext api.err.InvalidObject].freeze

    # Site-scoped Network application endpoints that are plain GETs, as
    # `method_name => path`. Defined as data so adding an endpoint does not
    # mean repeating a method body; anything needing arguments, a different
    # verb, or post-processing is written out explicitly below.
    NETWORK_ENDPOINTS = {
      # Core — present on every Network application version we support.
      firewall_rules:  '/rest/firewallrule',
      firewall_groups: '/rest/firewallgroup',
      port_forwards:   '/rest/portforward',
      networks:        '/rest/networkconf',
      dhcp_leases:     '/rest/user',
      devices:         '/stat/device',
      sysinfo:         '/stat/sysinfo',
      clients:         '/stat/sta',

      # Audit endpoints. Availability varies by Network application version
      # and by credential privilege, so all of them are listed in
      # OPTIONAL_ENDPOINTS and reached through #optional.
      wlans:           '/rest/wlanconf',
      settings:        '/get/setting',
      health:          '/stat/health',
      port_profiles:   '/rest/portconf',
      routes:          '/rest/routing',
      dynamic_dns:     '/rest/dynamicdns',
      radius_profiles: '/rest/radiusprofile',
      radius_accounts: '/rest/account',
      user_groups:     '/rest/usergroup',
      dpi_apps:        '/rest/dpiapp'
    }.freeze

    # Core endpoints every supported controller exposes. A failure here is a
    # real error, not a degradation.
    CORE_ENDPOINTS = %i[firewall_rules firewall_groups port_forwards networks
                        dhcp_leases devices sysinfo clients].freeze

    # UniFi OS console endpoints. These sit outside the Network application
    # proxy and return bare JSON rather than the {meta, data} envelope.
    OS_ENDPOINTS = {
      os_system: '/api/system'
    }.freeze

    # Endpoints an audit must be able to run without. #optional swallows an
    # EndpointUnavailable from any of these and records it in #degradations.
    OPTIONAL_ENDPOINTS = (
      (NETWORK_ENDPOINTS.keys - CORE_ENDPOINTS) +
      OS_ENDPOINTS.keys +
      %i[alarms events ips_events rogue_aps admins site_stats os_users]
    ).freeze

    attr_reader :site

    def initialize(host:, site: 'default', verify_ssl: false, username: nil, password: nil,
                   api_key: nil, verbose: false, timeout: nil, transport: nil)
      raise ArgumentError, 'Provide either api_key or username+password' if api_key.nil? && (username.nil? || password.nil?)

      @host         = host
      @api_key      = api_key
      @username     = username
      @password     = password
      @site         = site
      @token        = nil
      @csrf_token   = nil
      @cache        = {}
      @degradations = {}
      @transport    = transport ||
                      CurlTransport.new(verify_ssl: verify_ssl, verbose: verbose,
                                        timeout: timeout || CurlTransport::DEFAULT_TIMEOUT)
    end

    NETWORK_ENDPOINTS.each do |name, path|
      define_method(name) { network_get(path) }
    end

    OS_ENDPOINTS.each do |name, path|
      define_method(name) { os_get(path) }
    end

    # Recent alarms: the system log at warning severity and above. Archived
    # alarms are excluded by default — an audit cares about what is still
    # outstanding.
    def alarms(within: 24, archived: false, limit: 500)
      entries = system_log(within: within, limit: limit, severities: SystemLog::ALARM_SEVERITIES) do
        network_get('/stat/alarm', within: within, archived: archived)
      end
      archived ? entries : entries.reject { |e| SystemLog.archived?(e) }
    end

    def events(within: 24, limit: 500)
      system_log(within: within, limit: limit) do
        network_get('/stat/event', within: within, _limit: limit)
      end
    end

    # IDS/IPS detections: the SECURITY category of the system log. Only
    # present when Threat Management is licensed and enabled, so this is one
    # of the endpoints most likely to degrade.
    def ips_events(within: 24, limit: 500)
      system_log(within: within, limit: limit, categories: SystemLog::THREAT_CATEGORIES) do
        network_get('/stat/ips/event', within: within, _limit: limit)
      end
    end

    # Access points seen nearby that this site does not manage.
    def rogue_aps(within: 24)
      network_get('/stat/rogueap', within: within)
    end

    # Site administrators. The controller lists every administrator it has,
    # each with the sites they hold a role on, so this keeps the ones who can
    # administer this site. A credential without the right to read the list
    # answers 401/403 — the case #optional exists to absorb.
    def admins
      controller_get('/stat/admin').select { |a| AdminAccount.member_of?(a, @site) }
    end

    # UniFi OS console users, from the OS's own user service.
    def os_users
      os_get('/proxy/users/api/v2/users').fetch('data', [])
    end

    # Daily rollups for the site, used to compare current readings against a
    # recent baseline. +attrs+ names the counters to return.
    def site_stats(days: 7, attrs: %w[bytes wan-tx_bytes wan-rx_bytes wlan_bytes num_sta time])
      now   = (Time.now.to_f * 1000).to_i
      start = now - (days * 24 * 60 * 60 * 1000)
      network_post('/stat/report/daily.site', body: { attrs: attrs, start: start, end: now })
    end

    def gateway_device = self.class.gateway_of(devices)

    # Which device carries the gateway/controller figures — WAN state,
    # storage, memory. Defined here rather than inline so the audit
    # context picks the same device this does.
    def self.gateway_of(devices)
      devices.find { |d| d['type'] == 'udm' } ||
        devices.find { |d| d.key?('sys_stats') } ||
        devices.first
    end

    # Calls an endpoint that may not be available, returning nil instead of
    # raising when the controller refuses it. The reason is recorded in
    # #degradations so a caller can report a check as skipped rather than
    # silently passing it.
    def optional(name, **args)
      unless OPTIONAL_ENDPOINTS.include?(name)
        raise ArgumentError, "#{name} is not an optional endpoint"
      end
      return nil if @degradations.key?(name)

      public_send(name, **args)
    rescue EndpointUnavailable => e
      @degradations[name] = e.message
      nil
    end

    # Endpoint name => reason, for every optional endpoint this client tried
    # and could not reach.
    def degradations = @degradations.dup

    def degraded?(name) = @degradations.key?(name)

    # Turns PoE on ('auto') or off for a single port on the given device,
    # preserving any other ports' existing overrides.
    def set_port_poe(device:, port_idx:, enabled:)
      overrides = (device['port_overrides'] || []).map(&:dup)
      mode      = enabled ? 'auto' : 'off'

      if (entry = overrides.find { |o| o['port_idx'] == port_idx })
        entry['poe_mode'] = mode
      else
        overrides << { 'port_idx' => port_idx, 'poe_mode' => mode }
      end

      network_put("/rest/device/#{device['_id']}", body: { 'port_overrides' => overrides })
    end

    def login
      response = request(:post, '/api/auth/login',
                         body: { username: @username, password: @password })

      unless (200..299).cover?(response.status)
        raise AuthError, "Authentication failed (#{response.status}): #{error_message(response.body)}"
      end

      cookie_str  = response.headers.grep(/\Aset-cookie:/i).join('; ')
      @token      = cookie_str[/TOKEN=([^;]+)/i, 1] || cookie_str[/unifises=([^;]+)/i, 1]

      csrf_line   = response.headers.find { |h| h.match?(/\Ax-csrf-token:/i) }
      @csrf_token = csrf_line&.split(':', 2)&.last&.strip
      @csrf_token ||= csrf_from_body(response.body)

      raise AuthError, 'No session token received — check credentials' unless @token
      true
    end

    # Drops every memoized response. Called after a write, and available to
    # callers that need to re-read a controller they just changed.
    def clear_cache!
      @cache.clear
      self
    end

    private

    # Responses are memoized for the life of the client: an audit reads the
    # same endpoints from many independent checks, and the controller should
    # see one request per endpoint rather than one per check.
    def network_get(path, **params)
      cached(:network, path, params) do
        send_api(:get, network_path(path), params: params, endpoint: path)
      end
    end

    def network_post(path, body:)
      cached(:network_post, path, body) do
        send_api(:post, network_path(path), body: body, endpoint: path)
      end
    end

    def os_get(path)
      cached(:os, path, {}) do
        send_api(:get, path, endpoint: path, envelope: false)
      end
    end

    # A Network application endpoint that is not site-scoped.
    def controller_get(path)
      cached(:controller, path, {}) do
        send_api(:get, "/proxy/network/api#{path}", endpoint: path)
      end
    end

    # One page of the system log, newest first, filtered to +categories+
    # and +severities+ when given. Falls back to the block — the legacy
    # endpoint the log replaced — on a controller too old to serve it, and
    # reports both refusals if neither answers.
    #
    # Cached on the logical arguments rather than the request body, since the
    # body carries the time of the call.
    def system_log(within:, limit:, categories: nil, severities: nil)
      cached(:system_log, 'all', [within, limit, categories, severities]) do
        now  = (Time.now.to_f * 1000).to_i
        body = { pageNumber: 0, pageSize: limit, timestampFrom: now - (within * 60 * 60 * 1000), timestampTo: now }
        body[:categories] = categories if categories
        body[:severities] = severities if severities

        begin
          send_api(:post, "#{V2_PREFIX}/#{@site}/system-log/all", body: body, endpoint: '/system-log/all')
        rescue EndpointUnavailable => v2_error
          begin
            yield
          rescue EndpointUnavailable => legacy_error
            raise EndpointUnavailable.new("#{v2_error.message}; #{legacy_error.message}",
                                          endpoint: legacy_error.endpoint, status: legacy_error.status)
          end
        end
      end
    end

    def network_put(path, body:)
      result = send_api(:put, network_path(path), body: body, endpoint: path)
      clear_cache!
      result
    end

    def cached(scope, path, params)
      key = [scope, path, params]
      return @cache[key] if @cache.key?(key)

      @cache[key] = yield
    end

    def network_path(path) = "#{NETWORK_PREFIX}/#{@site}#{path}"

    # Issues the request, refreshing an expired session once before giving up.
    def send_api(method, path, endpoint:, params: {}, body: nil, envelope: true)
      ensure_authenticated
      response = request(method, path, params: params, body: body)

      if response.status == 401 && !@api_key && @token
        @token = @csrf_token = nil
        login
        response = request(method, path, params: params, body: body)
      end

      parse_response(response, endpoint: endpoint, envelope: envelope)
    end

    def ensure_authenticated
      return if @api_key

      login unless @token
    end

    def request(method, path, params: {}, body: nil)
      @transport.request(
        method:  method,
        url:     build_url(path, params),
        headers: build_headers(body),
        body:    body && JSON.generate(body)
      )
    rescue CurlTransport::TransportError => e
      raise ApiError, e.message
    end

    def build_headers(body)
      headers = []
      if @api_key
        headers << CurlTransport::Header.new(name: 'X-API-Key', value: @api_key, secret: true)
      else
        headers << CurlTransport::Header.new(name: 'Cookie', value: "TOKEN=#{@token}", secret: true) if @token
        headers << CurlTransport::Header.new(name: 'X-Csrf-Token', value: @csrf_token, secret: true) if @csrf_token
      end
      headers << CurlTransport::Header.new(name: 'Content-Type', value: 'application/json', secret: false) if body
      headers
    end

    def build_url(path, params = {})
      base = @host.match?(%r{\Ahttps?://}) ? @host : "https://#{@host}"
      url  = URI.join(base, path)
      url.query = URI.encode_www_form(params) unless params.nil? || params.empty?
      url.to_s
    end

    def parse_response(response, endpoint:, envelope: true)
      if UNAVAILABLE_STATUSES.include?(response.status)
        raise EndpointUnavailable.new(
          "#{endpoint} unavailable (HTTP #{response.status}#{unavailable_hint(response.status)})",
          endpoint: endpoint, status: response.status
        )
      end

      unless (200..299).cover?(response.status)
        raise ApiError, "API error (HTTP #{response.status}): #{error_message(response.body)}"
      end

      data = JSON.parse(response.body)
      return data unless envelope
      # v2 endpoints answer with a bare list, or {data, page_number, ...}
      # without a meta block; the legacy ones wrap everything in {meta, data}.
      return data if data.is_a?(Array)

      if data.dig('meta', 'rc') == 'error'
        msg = data.dig('meta', 'msg').to_s
        if UNAVAILABLE_ERRORS.include?(msg)
          raise EndpointUnavailable.new("#{endpoint} unavailable (#{msg})", endpoint: endpoint, status: response.status)
        end

        raise ApiError, "API error: #{msg}"
      end

      data['data']
    rescue JSON::ParserError => e
      raise ApiError, "Invalid JSON response from #{endpoint}: #{e.message}"
    end

    def unavailable_hint(status)
      case status
      when 401, 403 then ' — this credential is not permitted to read it'
      when 404, 405, 501 then ' — this controller version does not provide it'
      else ''
      end
    end

    # Older controllers return the CSRF token in the login body rather than a
    # header. `data` is an array on most versions, so this cannot dig blindly.
    def csrf_from_body(body)
      data = JSON.parse(body)['data']
      data['csrf_token'] if data.is_a?(Hash)
    rescue JSON::ParserError
      nil
    end

    # Legacy endpoints carry the reason in meta.msg, v2 ones in `message`.
    def error_message(body)
      parsed = JSON.parse(body)
      parsed.dig('meta', 'msg') || parsed['message'] || 'unknown error'
    rescue StandardError
      'unknown error'
    end
  end
end
