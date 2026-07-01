require 'open3'
require 'json'
require 'uri'
require 'tempfile'

module UiManage
  class Client
    class ApiError  < StandardError; end
    class AuthError < StandardError; end

    NETWORK_PREFIX = '/proxy/network/api/s'

    def initialize(host:, site: 'default', verify_ssl: false, username: nil, password: nil, api_key: nil, verbose: false)
      raise ArgumentError, 'Provide either api_key or username+password' if api_key.nil? && (username.nil? || password.nil?)

      @host       = host
      @api_key    = api_key
      @username   = username
      @password   = password
      @site       = site
      @verify_ssl = verify_ssl
      @verbose    = verbose
      @token      = nil
      @csrf_token = nil
    end

    def firewall_rules  = network_get('/rest/firewallrule')
    def firewall_groups = network_get('/rest/firewallgroup')
    def port_forwards   = network_get('/rest/portforward')
    def networks        = network_get('/rest/networkconf')
    def dhcp_leases     = network_get('/rest/user')
    def devices         = network_get('/stat/device')
    def sysinfo         = network_get('/stat/sysinfo')
    def clients         = network_get('/stat/sta')

    def gateway_device
      devs = devices
      devs.find { |d| d['type'] == 'udm' } ||
        devs.find { |d| d.key?('sys_stats') } ||
        devs.first
    end

    def login
      raw              = fetch(:post, '/api/auth/login',
                           body:            JSON.generate(username: @username, password: @password),
                           include_headers: true)
      headers, body    = split_response(raw)
      code             = http_status(headers)

      unless (200..299).cover?(code)
        raise AuthError, "Authentication failed (#{code}): #{safe_error(body)}"
      end

      cookie_str  = headers.grep(/\Aset-cookie:/i).join('; ')
      @token      = cookie_str[/TOKEN=([^;]+)/i, 1] || cookie_str[/unifises=([^;]+)/i, 1]

      csrf_line   = headers.find { |h| h.match?(/\Ax-csrf-token:/i) }
      @csrf_token = csrf_line&.split(':', 2)&.last&.strip
      @csrf_token ||= begin
        JSON.parse(body).dig('data', 'csrf_token')
      rescue
        nil
      end

      raise AuthError, 'No session token received — check credentials' unless @token
      true
    end

    private

    def network_get(path)
      ensure_authenticated
      parse_response fetch(:get, "#{NETWORK_PREFIX}/#{@site}#{path}")
    end

    def ensure_authenticated
      return if @api_key
      login unless @token
    end

    # Secrets (API key, session cookie, CSRF token, login body) are passed to curl
    # via a -K config file rather than argv, since argv is visible to other local
    # users through `ps`/procfs for the life of the subprocess.
    def fetch(method, path, body: nil, include_headers: false)
      url  = build_url(path)
      args = base_args
      args << '-i' if include_headers
      args.concat(['-X', method.to_s.upcase])

      headers      = build_headers(body)
      config_lines = headers.map { |h| header_directive("#{h[:name]}: #{h[:value]}") }
      config_lines << "data = #{quote(body)}" if body

      warn redacted_command(args, headers, body, url) if @verbose

      Tempfile.create('ui-manage-curl') do |f|
        File.chmod(0o600, f.path)
        f.write(config_lines.join("\n"))
        f.flush

        stdout, stderr, status = Open3.capture3('curl', '-K', f.path, *args, url)
        unless status.success?
          raise ApiError, "curl failed (exit #{status.exitstatus}): #{stderr.strip}"
        end
        stdout
      end
    rescue Errno::ENOENT
      raise ApiError, 'curl not found in PATH'
    end

    def build_headers(body)
      headers = []
      if @api_key
        headers << { name: 'X-API-Key', value: @api_key, secret: true }
      else
        headers << { name: 'Cookie', value: "TOKEN=#{@token}", secret: true }      if @token
        headers << { name: 'X-Csrf-Token', value: @csrf_token, secret: true }      if @csrf_token
      end
      headers << { name: 'Content-Type', value: 'application/json', secret: false } if body
      headers
    end

    def header_directive(value)
      "header = #{quote(value)}"
    end

    # Escapes a value for curl's -K config file string syntax (backslash and
    # double-quote are the only special characters there).
    def quote(value)
      '"' + value.gsub('\\', '\\\\\\\\').gsub('"', '\\"') + '"'
    end

    # Reconstructs a human-readable curl command line for --verbose output.
    # Secret header values and the request body (which may carry a password)
    # are always redacted — never the real values, regardless of method/path.
    def redacted_command(args, headers, body, url)
      parts = ['curl', *args]
      headers.each do |h|
        value = h[:secret] ? '***REDACTED***' : h[:value]
        parts.concat(['-H', "#{h[:name]}: #{value}"])
      end
      parts.concat(['-d', '***REDACTED***']) if body
      parts << url
      '+ ' + parts.map { |p| shell_quote(p) }.join(' ')
    end

    def shell_quote(str)
      return str if str.match?(/\A[\w.\-\/:@]+\z/)
      "'" + str.gsub("'", "'\\\\''") + "'"
    end

    def base_args
      args = ['--silent', '--show-error', '--max-time', '30',
              '-H', 'Accept: application/json']
      args << '--insecure' unless @verify_ssl
      args
    end

    def build_url(path)
      base = @host.match?(%r{\Ahttps?://}) ? @host : "https://#{@host}"
      URI.join(base, path).to_s
    end

    def parse_response(body)
      data = JSON.parse(body)
      raise ApiError, "API error: #{data.dig('meta', 'msg')}" if data.dig('meta', 'rc') == 'error'
      data['data']
    rescue JSON::ParserError => e
      raise ApiError, "Invalid JSON response: #{e.message}"
    end

    # curl -i output: one or more HTTP header blocks separated by blank lines,
    # followed by the body. We use the last header block to skip 1xx and redirect
    # header blocks.
    def split_response(raw)
      blocks           = raw.split(/\r?\n\r?\n/)
      last_header_idx  = blocks.rindex { |b| b.match?(/\AHTTP\//i) } || 0
      headers          = blocks[last_header_idx].split(/\r?\n/)
      body             = blocks[(last_header_idx + 1)..].join("\n\n")
      [headers, body]
    end

    def http_status(headers)
      headers.first.to_s.split(' ', 3)[1].to_i
    end

    def safe_error(body)
      JSON.parse(body).dig('meta', 'msg') || 'unknown error'
    rescue
      'unknown error'
    end
  end
end
