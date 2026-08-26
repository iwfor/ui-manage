require_relative 'test_helper'

module UiManage
  class TransportTest < TestCase
    def transport(**args) = CurlTransport.new(**args)

    def header(name, value, secret: false)
      CurlTransport::Header.new(name: name, value: value, secret: secret)
    end

    # --- response parsing -----------------------------------------------------

    def test_parses_status_headers_and_body
      raw = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}"
      res = transport.send(:parse, raw)

      assert_equal 200, res.status
      assert_equal '{"ok":true}', res.body
      assert_includes res.headers, 'Content-Type: application/json'
    end

    def test_uses_the_last_header_block_so_redirects_and_1xx_are_skipped
      raw = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 302 Found\r\nLocation: /x\r\n\r\n" \
            "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{\"rc\":\"error\"}"
      res = transport.send(:parse, raw)

      assert_equal 403, res.status
      assert_equal '{"rc":"error"}', res.body
    end

    def test_an_empty_body_parses_without_raising
      res = transport.send(:parse, "HTTP/1.1 204 No Content\r\n\r\n")

      assert_equal 204, res.status
      assert_equal '', res.body
    end

    def test_a_body_containing_a_blank_line_is_kept_whole
      raw = "HTTP/1.1 200 OK\r\n\r\nfirst\n\nsecond"

      assert_equal "first\n\nsecond", transport.send(:parse, raw).body
    end

    # --- curl config escaping -------------------------------------------------

    def test_quoting_escapes_backslashes_and_double_quotes
      assert_equal '"a\\"b"',   transport.send(:quote, 'a"b')
      assert_equal '"a\\\\b"',  transport.send(:quote, 'a\\b')
    end

    def test_quoting_escapes_every_character_curl_treats_specially
      quoted = transport.send(:quote, %W[a\tb\nc\rd\ve].join)

      assert_equal '"a\\tb\\nc\\rd\\ve"', quoted
    end

    # curl's -K parser is line-oriented, so a value carrying a raw newline would
    # end the directive and let the rest be read as a new one.
    def test_a_quoted_value_cannot_break_out_of_its_directive
      quoted = transport.send(:quote, %(x"\nproxy = "http://attacker.test))

      assert_equal 1, quoted.lines.size
      refute_includes quoted, "\n"
      assert quoted.start_with?('"')
      assert quoted.end_with?('"')
    end

    def test_a_header_carrying_control_characters_is_refused
      error = assert_raises(CurlTransport::TransportError) do
        transport.request(method: :get, url: 'https://unifi.test/api',
                          headers: [header('X-API-Key', "key\nproxy = http://attacker.test", secret: true)])
      end

      assert_includes error.message, 'X-API-Key'
      refute_includes error.message, 'attacker.test'
    end

    def test_a_header_name_carrying_a_colon_is_refused
      assert_raises(CurlTransport::TransportError) do
        transport.request(method: :get, url: 'https://unifi.test/api',
                          headers: [header('X: Injected', 'value')])
      end
    end

    # --- verbose redaction ----------------------------------------------------

    def test_secret_headers_and_bodies_are_redacted_in_verbose_output
      line = transport.send(
        :redacted_command,
        ['--silent'],
        [header('X-API-Key', 'sekrit', secret: true),
         header('Cookie', 'TOKEN=abc', secret: true),
         header('Content-Type', 'application/json')],
        '{"password":"hunter2"}',
        'https://unifi.test/api'
      )

      refute_includes line, 'sekrit'
      refute_includes line, 'TOKEN=abc'
      refute_includes line, 'hunter2'
      assert_includes line, '***REDACTED***'
      assert_includes line, 'Content-Type: application/json'
      assert_includes line, 'https://unifi.test/api'
    end

    def test_verbose_output_shell_quotes_arguments
      line = transport.send(:redacted_command, [], [header('X', 'a b; rm -rf /')], nil, 'https://unifi.test')

      assert_includes line, "'X: a b; rm -rf /'"
    end

    # --- curl arguments -------------------------------------------------------

    def test_tls_verification_is_off_by_default_and_on_when_asked
      assert_includes transport.send(:base_args), '--insecure'
      refute_includes transport(verify_ssl: true).send(:base_args), '--insecure'
    end

    def test_the_timeout_is_passed_to_curl
      args = transport(timeout: 90).send(:base_args)

      assert_equal '90', args[args.index('--max-time') + 1]
    end

    # --- end to end -----------------------------------------------------------

    def test_a_real_request_reaches_curl_and_never_puts_secrets_in_argv
      seen_argv = nil
      fake      = <<~SH
        #!/bin/sh
        echo "$@" > "#{argv_log}"
        printf 'HTTP/1.1 200 OK\\r\\n\\r\\n{"meta":{"rc":"ok"},"data":[]}'
      SH
      with_fake_curl(fake) do
        res = transport.request(
          method:  :get,
          url:     'https://unifi.test/api/x',
          headers: [header('X-API-Key', 'sekrit', secret: true)]
        )
        assert_equal 200, res.status
        seen_argv = File.read(argv_log)
      end

      refute_includes seen_argv, 'sekrit'
      assert_includes seen_argv, '-K'
    end

    def test_a_failing_curl_becomes_a_transport_error
      fake = "#!/bin/sh\necho 'could not resolve host' >&2\nexit 6\n"
      with_fake_curl(fake) do
        error = assert_raises(CurlTransport::TransportError) do
          transport.request(method: :get, url: 'https://unifi.test/api/x')
        end
        assert_includes error.message, 'exit 6'
        assert_includes error.message, 'could not resolve host'
      end
    end

    def test_a_missing_curl_is_reported_clearly
      with_path(File.join(TEST_CONFIG_DIR, 'empty-bin')) do
        error = assert_raises(CurlTransport::TransportError) do
          transport.request(method: :get, url: 'https://unifi.test/api/x')
        end
        assert_includes error.message, 'curl not found in PATH'
      end
    end

    private

    def argv_log = File.join(TEST_CONFIG_DIR, 'curl-argv.log')

    # Puts a stub `curl` at the front of PATH so the transport can be exercised
    # end to end without a network or a real controller.
    def with_fake_curl(script)
      dir = File.join(TEST_CONFIG_DIR, 'fake-bin')
      FileUtils.mkdir_p(dir)
      path = File.join(dir, 'curl')
      File.write(path, script)
      File.chmod(0o755, path)
      with_path(dir) { yield }
    ensure
      FileUtils.rm_rf(dir)
      FileUtils.rm_f(argv_log)
    end

    def with_path(dir)
      FileUtils.mkdir_p(dir)
      original = ENV['PATH']
      ENV['PATH'] = dir
      yield
    ensure
      ENV['PATH'] = original
    end
  end
end
