module UiManage
  module Audit
    # Runs checks against a context and collects the results.
    class Runner
      def initialize(context:, checks: nil)
        @context = context
        @checks  = checks || Registry.select(settings: context.settings)
      end

      def run
        suppressed = 0

        results = @checks.map do |check_class|
          result = run_one(check_class)

          if result.failed?
            kept        = result.findings.reject { |f| @context.settings.suppressed_finding?(f) }
            suppressed += result.findings.size - kept.size
            result      = kept.empty? ? Result.pass(check_class) : Result.fail(check_class, kept)
          end

          result
        end

        Report.new(results: results, suppressed: suppressed)
      end

      private

      # A check whose data the controller would not serve is skipped with the
      # reason recorded when the endpoint was refused — never run against nil,
      # and never reported as passing.
      def run_one(check_class)
        missing = check_class.requires.reject { |name| @context.available?(name) }
        return check_class.new(@context).call if missing.empty?

        Result.skip(check_class, missing_reason(missing))
      end

      def missing_reason(missing)
        missing.map { |name| @context.unavailable_reason(name) || "#{name} unavailable" }
               .uniq
               .join('; ')
      end
    end
  end
end
