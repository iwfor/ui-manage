module UiManage
  module Audit
    # Base class for audit checks.
    #
    # A check declares what it is and what data it needs, then implements
    # #run and calls #finding for anything wrong. It never has to handle a
    # missing endpoint: `requires` is what lets the runner skip the check with
    # the reason Phase 1 recorded, so a check body can assume its data is
    # there.
    #
    #   class OpenWlan < Audit::Check
    #     id          :wlan_open
    #     title       'SSID with no or broken encryption'
    #     category    :security
    #     severity    :critical
    #     requires    :wlans
    #     remediation 'Settings > WiFi > (SSID) > Security: choose WPA2 or WPA3.'
    #
    #     def run
    #       data(:wlans).each do |wlan|
    #         finding(subject: wlan['name'], message: '...') if bad?(wlan)
    #       end
    #     end
    #   end
    class Check
      class SkipCheck < StandardError; end

      class << self
        # Every subclass registers itself, so adding a check file is all it
        # takes to add a check.
        def inherited(subclass)
          super
          Registry.register(subclass)
        end

        # Each of these reads its value when called with an argument and
        # returns it when called without, which is what makes the class body
        # read as a declaration.
        %i[id title category severity remediation].each do |attribute|
          define_method(attribute) do |value = nil|
            if value.nil?
              instance_variable_get("@#{attribute}")
            else
              instance_variable_set("@#{attribute}", value)
            end
          end
        end

        # Endpoints this check cannot run without. The runner skips the check
        # when any of them is unavailable.
        def requires(*names)
          @requires = names.flatten unless names.empty?
          @requires || []
        end

        def to_h
          { 'id' => id.to_s, 'title' => title, 'category' => category.to_s,
            'severity' => severity.to_s, 'remediation' => remediation, 'requires' => requires.map(&:to_s) }.compact
        end
      end

      attr_reader :context, :findings

      def initialize(context)
        @context  = context
        @findings = []
      end

      # Runs the check body and turns whatever it did into a Result. Errors
      # are caught here: one check with a bug must not end an audit, and its
      # failure must not be mistaken for a clean pass.
      def call
        run
        findings.empty? ? Result.pass(self.class) : Result.fail(self.class, findings)
      rescue SkipCheck => e
        Result.skip(self.class, e.message)
      rescue StandardError => e
        Result.error(self.class, "#{e.class}: #{e.message}")
      end

      def run
        raise NotImplementedError, "#{self.class} must implement #run"
      end

      # --- what a check body calls ------------------------------------------

      def data(name) = context.data(name)

      def threshold(name) = context.threshold(name)

      def policy(name) = context.policy(name)

      # A named section of /get/setting, or nil when the controller has none.
      def setting(key) = context.setting(key)

      def finding(message:, subject: nil, severity: nil, evidence: nil)
        findings << Finding.new(
          check_id:    self.class.id,
          severity:    severity || self.class.severity,
          subject:     subject,
          message:     message,
          evidence:    evidence,
          remediation: self.class.remediation
        )
      end

      # Ends the check as "not checked", with a reason. For when the data is
      # present but does not say enough to judge — a setting the controller
      # does not report, say. A check must never pass by default in that case.
      def skip!(reason) = raise(SkipCheck, reason)
    end
  end
end
