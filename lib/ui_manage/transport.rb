require 'open3'
require 'tempfile'

module UiManage
  # Performs HTTP requests by shelling out to curl.
  #
  # Client reaches the network only through this class, which keeps the
  # subprocess and secret-handling rules in one place and lets tests
  # substitute a fake transport (see test/support/fake_transport.rb) instead
  # of talking to a real controller.
  class CurlTransport
    class TransportError < StandardError; end

    DEFAULT_TIMEOUT = 30

    # The escape sequences curl recognizes inside a quoted config-file value.
    CONFIG_ESCAPES = {
      "\\" => "\\\\",
      '"'  => '\\"',
      "\t" => '\\t',
      "\n" => '\\n',
      "\r" => '\\r',
      "\v" => '\\v'
    }.freeze

    # A header to send. +secret+ marks values that must never be echoed in
    # --verbose output (API keys, session cookies, CSRF tokens).
    Header = Struct.new(:name, :value, :secret, keyword_init: true) do
      def secret? = !!secret
    end

    Response = Struct.new(:status, :headers, :body, keyword_init: true)

    def initialize(verify_ssl: false, verbose: false, timeout: DEFAULT_TIMEOUT)
      @verify_ssl = verify_ssl
      @verbose    = verbose
      @timeout    = timeout
    end

    # Secrets (API key, session cookie, CSRF token, and request bodies, which
    # may carry a password) are passed to curl through a 0600 -K config file
    # rather than argv, since argv is visible to other local users through
    # `ps`/procfs for the life of the subprocess.
    #
    # Responses are always fetched with -i so the caller can act on the HTTP
    # status — an endpoint the credential may not read answers 401/403, which
    # is indistinguishable from success by body alone.
    def request(method:, url:, headers: [], body: nil)
      headers.each { |h| validate_header!(h) }

      args = base_args + ['-i', '-X', method.to_s.upcase]

      config_lines = headers.map { |h| "header = #{quote("#{h.name}: #{h.value}")}" }
      config_lines << "data = #{quote(body)}" if body

      warn redacted_command(args, headers, body, url) if @verbose

      parse(run_curl(config_lines, args, url))
    rescue Errno::ENOENT
      raise TransportError, 'curl not found in PATH'
    end

    private

    # A control character in a header would split the curl config directive
    # and, on the wire, inject a second header — neither is ever legitimate,
    # so refuse rather than sanitize. The offending value is never echoed: it
    # is a credential often enough to matter.
    def validate_header!(header)
      return unless header.name.to_s.match?(/[[:cntrl:]:]/) ||
                    header.value.to_s.match?(/[[:cntrl:]]/)

      raise TransportError,
            "Refusing to send the #{header.name} header: it contains control characters"
    end

    def run_curl(config_lines, args, url)
      Tempfile.create('ui-manage-curl') do |f|
        File.chmod(0o600, f.path)
        f.write(config_lines.join("\n"))
        f.flush

        stdout, stderr, status = Open3.capture3('curl', '-K', f.path, *args, url)
        unless status.success?
          raise TransportError, "curl failed (exit #{status.exitstatus}): #{stderr.strip}"
        end
        stdout
      end
    end

    def base_args
      args = ['--silent', '--show-error', '--max-time', @timeout.to_s,
              '-H', 'Accept: application/json']
      args << '--insecure' unless @verify_ssl
      args
    end

    # curl -i output: one or more HTTP header blocks separated by blank lines,
    # followed by the body. We use the last header block to skip 1xx and
    # redirect header blocks.
    def parse(raw)
      blocks          = raw.split(/\r?\n\r?\n/)
      last_header_idx = blocks.rindex { |b| b.match?(/\AHTTP\//i) } || 0
      headers         = blocks[last_header_idx].split(/\r?\n/)
      body            = blocks[(last_header_idx + 1)..].to_a.join("\n\n")

      Response.new(status: status_from(headers), headers: headers, body: body)
    end

    def status_from(headers)
      headers.first.to_s.split(' ', 3)[1].to_i
    end

    # Escapes a value for curl's -K config file string syntax. The config file
    # is line-oriented, so a raw newline inside a value would end the directive
    # and let whatever followed be parsed as a new one (`proxy = ...`, say);
    # every character curl gives an escape sequence to is escaped here rather
    # than emitted literally.
    def quote(value)
      '"' + value.to_s.gsub(/[\\"\t\n\r\v]/) { |c| CONFIG_ESCAPES[c] } + '"'
    end

    # Reconstructs a human-readable curl command line for --verbose output.
    # Secret header values and the request body are always redacted — never
    # the real values, regardless of method or path.
    def redacted_command(args, headers, body, url)
      parts = ['curl', *args]
      headers.each do |h|
        parts.concat(['-H', "#{h.name}: #{h.secret? ? '***REDACTED***' : h.value}"])
      end
      parts.concat(['-d', '***REDACTED***']) if body
      parts << url
      '+ ' + parts.map { |p| shell_quote(p) }.join(' ')
    end

    def shell_quote(str)
      return str if str.match?(%r{\A[\w.\-/:@]+\z})
      "'" + str.gsub("'", "'\\\\''") + "'"
    end
  end
end
