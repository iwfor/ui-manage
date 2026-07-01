module UiManage
  # Replaces identifying values (IPs, MACs, serials, device IDs) with
  # realistic-looking placeholders, so command output can be shared (screenshots,
  # support tickets, bug reports) without exposing real network details.
  #
  # The same real value always maps to the same placeholder within one
  # Anonymizer instance, so entries stay cross-referenceable across sections of
  # a report. When disabled, every method is a no-op passthrough.
  class Anonymizer
    # RFC 5737 documentation ranges — reserved for exactly this purpose, so a
    # reader immediately recognizes them as placeholders rather than real hosts.
    IP_BLOCKS = ['192.0.2', '198.51.100', '203.0.113'].freeze
    IP_WILDCARDS = %w[0.0.0.0 0.0.0.0/0 255.255.255.255].freeze

    MAC_RE = /\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b/
    IP_RE  = /\b\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?\b/

    def initialize(enabled = false)
      @enabled    = !!enabled
      @ips        = {}
      @macs       = {}
      @serials    = {}
      @device_ids = {}
    end

    def enabled? = @enabled

    def ip(value)
      return value unless @enabled
      return value if value.nil? || value.to_s.empty?
      return value if IP_WILDCARDS.include?(value.to_s)

      @ips[value] ||= begin
        n     = @ips.size
        block = IP_BLOCKS[(n / 254) % IP_BLOCKS.length]
        octet = (n % 254) + 1
        "#{block}.#{octet}"
      end
    end

    def mac(value)
      return value unless @enabled
      return value if value.nil? || value.to_s.empty?

      @macs[value] ||= begin
        n = @macs.size
        # 02:00:00 is a locally-administered OUI prefix — never assigned to real
        # hardware, so it reads as obviously synthetic.
        format('02:00:00:%02X:%02X:%02X', (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF)
      end
    end

    def serial(value)
      return value unless @enabled
      return value if value.nil? || value.to_s.empty?

      @serials[value] ||= format('ANON%08d', @serials.size + 1)
    end

    def device_id(value)
      return value unless @enabled
      return value if value.nil? || value.to_s.empty?

      @device_ids[value] ||= format('%024x', @device_ids.size + 1)
    end

    # Scans free-form text for embedded IPs (with optional /cidr) and MACs and
    # replaces just those substrings, leaving the rest of the text intact.
    def scrub(text)
      return text unless @enabled
      return text if text.nil? || text.to_s.empty?

      s = text.to_s
      s = s.gsub(MAC_RE) { |m| mac(m) }
      s = s.gsub(IP_RE) do |m|
        next m if IP_WILDCARDS.include?(m)

        ip_part, _, cidr = m.partition('/')
        cidr.empty? ? ip(ip_part) : "#{ip(ip_part)}/#{cidr}"
      end
      s
    end

    # Recursively scrubs IPs/MACs out of an arbitrary JSON-shaped structure
    # (Hash/Array/String), leaving other value types untouched.
    def deep_scrub(obj)
      case obj
      when Hash   then obj.each_with_object({}) { |(k, v), h| h[k] = deep_scrub(v) }
      when Array  then obj.map { |v| deep_scrub(v) }
      when String then scrub(obj)
      else obj
      end
    end
  end
end
