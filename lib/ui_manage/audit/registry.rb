module UiManage
  module Audit
    # Every check that has been defined. Subclasses of Check register
    # themselves, so adding a file under audit/checks/ is all it takes.
    module Registry
      module_function

      def register(check_class)
        checks << check_class unless checks.include?(check_class)
      end

      def checks = (@checks ||= [])

      # Loads every check file. Idempotent — the guard matters because
      # requiring twice would otherwise register duplicates.
      def load!
        return self if @loaded

        Dir[File.join(__dir__, 'checks', '*.rb')].sort.each { |f| require f }
        @loaded = true
        self
      end

      def all
        load!
        checks.reject { |c| c.id.nil? }.sort_by { |c| [c.category.to_s, c.id.to_s] }
      end

      def find(id) = all.find { |c| c.id.to_s == id.to_s }

      # Narrows the check list. +only+ and +skip+ accept exact ids or globs
      # ("wlan_*"), so a run can be aimed at one area without listing every id.
      def select(only: nil, skip: nil, category: nil, min_severity: nil, settings: nil)
        result = all
        result = result.select { |c| c.category.to_s == category.to_s } if category
        result = result.select { |c| Severity.at_or_above?(c.severity, min_severity) } if min_severity
        result = result.select { |c| match_any?(c, only) } if only && !Array(only).empty?
        result = result.reject { |c| match_any?(c, skip) } if skip && !Array(skip).empty?
        result = result.reject { |c| settings.suppressed_check?(c.id) } if settings
        result
      end

      def categories = all.map(&:category).uniq.sort_by(&:to_s)

      def match_any?(check, patterns)
        Array(patterns).any? { |p| File.fnmatch?(p.to_s, check.id.to_s) }
      end

      # Test seam: forgets everything registered so a test can define checks
      # without leaking them into other tests.
      def reset!
        @checks = []
        @loaded = false
        self
      end
    end
  end
end
