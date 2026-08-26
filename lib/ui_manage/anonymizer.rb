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
      @aliases    = {}
    end

    def enabled? = @enabled

    def ip(value)
      return value if IP_WILDCARDS.include?(value.to_s)

      placeholder(@ips, value) do |n|
        block = IP_BLOCKS[(n / 254) % IP_BLOCKS.length]
        "#{block}.#{(n % 254) + 1}"
      end
    end

    def mac(value)
      # 02:00:00 is a locally-administered OUI prefix — never assigned to real
      # hardware, so it reads as obviously synthetic.
      placeholder(@macs, value) do |n|
        format('02:00:00:%02X:%02X:%02X', (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF)
      end
    end

    def serial(value)
      placeholder(@serials, value) { |n| format('ANON%08d', n + 1) }
    end

    def device_id(value)
      placeholder(@device_ids, value) { |n| format('%024x', n + 1) }
    end

    # Names that identify a place or a person rather than a machine. IPs and
    # MACs follow a fixed format #scrub can recognise anywhere; a name like
    # "Guest" or "AP-Garage" does not, so it has to be replaced where the field
    # is read. Every value registered here is remembered and also replaced
    # wherever it later turns up in free text — so an audit finding naming an
    # SSID is anonymised along with the column that named it.
    def ssid(value) = named(value) { |n| "Network-#{n}" }

    def device_name(value) = named(value) { |n| "Device-#{n}" }

    def person(value) = named(value) { |n| "Person-#{n}" }

    def email(value) = named(value) { |n| "person#{n}@example.com" }

    # For a value whose kind is not known where it is read — an audit finding's
    # subject, which may be any of the above.
    def label(value) = named(value) { |n| "Name-#{n}" }

    # Scans free-form text for embedded IPs (with optional /cidr) and MACs and
    # replaces just those substrings, leaving the rest of the text intact.
    def scrub(text)
      return text unless @enabled
      return text if text.nil? || text.to_s.empty?

      s = replace_names(text.to_s)
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

    private

    # Registers a placeholder for a whole field value. Numbering is shared
    # across the kinds, so one original always maps to one placeholder
    # whichever helper saw it first.
    def named(value)
      return value unless @enabled
      return value if value.nil? || value.to_s.empty?

      @aliases[value.to_s] ||= yield(@aliases.size + 1)
    end

    # Longest first, so a name containing a shorter one is replaced whole
    # rather than having its substring swapped out from under it.
    def replace_names(text)
      return text if @aliases.empty?

      @aliases.keys.sort_by { |original| -original.length }
              .reduce(text) { |acc, original| acc.gsub(original, @aliases[original]) }
    end

    # Returns the stable placeholder for value, generating one from the cache
    # size on first sight; passes value through untouched when anonymization is
    # disabled or the value is blank.
    def placeholder(cache, value)
      return value unless @enabled
      return value if value.nil? || value.to_s.empty?

      cache[value] ||= yield(cache.size)
    end
  end
end
