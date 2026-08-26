module UiManage
  # Removes credentials from controller payloads before anything renders them.
  #
  # UniFi marks sensitive fields with an `x_` prefix (x_passphrase,
  # x_ssh_password, x_ipsec_pre_shared_key, x_secret), alongside a handful of
  # plainly-named ones in settings and RADIUS profiles. Audit output gets
  # pasted into tickets and chat, and nothing this tool needs to *display*
  # requires the real value — so redaction is unconditional rather than a
  # flag, and applies at the render boundary only. Checks that must reason
  # about a secret (passphrase length, say) run before this and see the raw
  # value.
  module Redactor
    PLACEHOLDER = '***REDACTED***'.freeze

    # `x_`-prefixed keys are UniFi's own convention for values it stores
    # encrypted. The rest catch the fields that don't follow it.
    SECRET_KEY = /\Ax_|password|passphrase|pre_shared|secret|private_key|psk|community|token|api_key/i

    def self.secret_key?(key) = key.to_s.match?(SECRET_KEY)

    def self.scrub(obj)
      case obj
      when Hash
        obj.each_with_object({}) { |(k, v), h| h[k] = secret_key?(k) ? redact(v) : scrub(v) }
      when Array
        obj.map { |v| scrub(v) }
      else
        obj
      end
    end

    # An absent or empty value is left as it is: "no SSH password is set" is
    # itself an audit finding, and a placeholder would hide the difference
    # between unset and set.
    def self.redact(value)
      return value if value.nil? || value == '' || value == false || value == []

      PLACEHOLDER
    end
  end
end
