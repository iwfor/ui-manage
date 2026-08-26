require 'json'
require 'uri'

# Stands in for CurlTransport so Client tests never shell out or touch the
# network. Records every request and answers with whatever the handler block
# returns.
class FakeTransport
  Request = Struct.new(:method, :url, :path, :query, :headers, :body, keyword_init: true) do
    # Headers as a name => value hash, for readable assertions.
    def header(name)
      headers.find { |h| h.name.casecmp?(name) }&.value
    end

    def secret_headers
      headers.select(&:secret?).map(&:name)
    end

    def json_body
      body && JSON.parse(body)
    end
  end

  attr_reader :requests

  def initialize(&handler)
    @handler  = handler
    @requests = []
  end

  def request(method:, url:, headers: [], body: nil)
    uri = URI.parse(url)
    req = Request.new(
      method:  method,
      url:     url,
      path:    uri.path,
      query:   uri.query ? URI.decode_www_form(uri.query).to_h : {},
      headers: headers,
      body:    body
    )
    @requests << req
    @handler.call(req) or raise("FakeTransport handler returned nothing for #{method.to_s.upcase} #{uri.path}")
  end

  def paths = requests.map(&:path)

  # --- response builders -----------------------------------------------------

  # A successful Network application response ({meta, data} envelope).
  def self.ok(data = [])
    response(200, JSON.generate('meta' => { 'rc' => 'ok' }, 'data' => data))
  end

  # A controller-level failure carried in the envelope rather than the status.
  def self.api_error(msg, status: 200)
    response(status, JSON.generate('meta' => { 'rc' => 'error', 'msg' => msg }))
  end

  def self.status(code, body = '')
    response(code, body)
  end

  # A bare-JSON response, as UniFi OS console endpoints return.
  def self.bare(obj, status: 200)
    response(status, JSON.generate(obj))
  end

  def self.login_ok(token: 'session-token', csrf: 'csrf-token')
    UiManage::CurlTransport::Response.new(
      status:  200,
      headers: ['HTTP/1.1 200 OK', "Set-Cookie: TOKEN=#{token}; Path=/; HttpOnly", "X-CSRF-Token: #{csrf}"],
      body:    JSON.generate('meta' => { 'rc' => 'ok' }, 'data' => [])
    )
  end

  def self.response(status, body)
    UiManage::CurlTransport::Response.new(
      status:  status,
      headers: ["HTTP/1.1 #{status} #{status == 200 ? 'OK' : 'Error'}"],
      body:    body
    )
  end
  private_class_method :response
end
