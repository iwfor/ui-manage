module UiManage
  module Audit
    # The data every check reads from, fetched once and shared.
    #
    # An audit reads the same endpoints from many independent checks, so this
    # sits in front of Client's own cache and additionally remembers which
    # endpoints came back unavailable — that record is what turns a would-be
    # failure into a skip with a reason.
    class Context
      attr_reader :client, :device, :settings

      def initialize(client:, device: {}, settings: nil)
        @client       = client
        @device       = device || {}
        @settings     = settings || Settings.new
        @cache        = {}
        @degradations = {}
      end

      # Reads an endpoint, returning nil when the controller would not serve
      # it. Checks do not call this expecting nil — `requires` means the
      # runner has already skipped them if it would be.
      def data(name)
        return @cache[name] if @cache.key?(name)

        @cache[name] = load(name)
      end

      def available?(name) = !data(name).nil?

      def unavailable_reason(name)
        data(name) # populates the reason as a side effect of trying
        @degradations[name] || client.degradations[name]
      end

      def threshold(name) = settings.threshold(name)

      # The gateway/controller device, where WAN, storage, and memory
      # figures live. nil when the device list could not be read.
      def gateway
        return @gateway if defined?(@gateway)

        devices  = data(:devices)
        @gateway = devices && Client.gateway_of(devices)
      end

      # A value from the device's audit policy — what the operator said this
      # network is supposed to look like. nil means they have not said.
      def policy(name) = device[name.to_s]

      # One section of /get/setting by its key, e.g. 'mgmt', 'super_cloudaccess'.
      def setting(key)
        sections = data(:settings)
        return nil if sections.nil?

        sections.find { |s| s['key'].to_s == key.to_s }
      end

      private

      def load(name)
        if Client::OPTIONAL_ENDPOINTS.include?(name)
          client.optional(name)
        else
          client.public_send(name)
        end
      rescue Client::EndpointUnavailable => e
        # A core endpoint can refuse too — a credential scoped to one site,
        # say. Treating it the same way keeps one unreachable endpoint from
        # ending the whole audit.
        @degradations[name] = e.message
        nil
      end
    end
  end
end
