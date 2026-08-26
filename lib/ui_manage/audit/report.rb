module UiManage
  module Audit
    # The outcome of a run: every result, and the summaries a caller needs to
    # print it or decide an exit status.
    class Report
      attr_reader :results, :suppressed

      def initialize(results:, suppressed: 0)
        @results    = results
        @suppressed = suppressed
      end

      def findings(min_severity: nil)
        all = results.flat_map(&:findings)
        all = all.select { |f| Severity.at_or_above?(f.severity, min_severity) } if min_severity
        all.sort_by { |f| [-Severity.rank(f.severity), f.check_id.to_s, f.subject.to_s] }
      end

      def failed  = results.select(&:failed?)
      def passed  = results.select(&:passed?)
      def skipped = results.select(&:skipped?)
      def errored = results.select(&:errored?)

      # Findings per severity, most severe first, omitting empty levels.
      def counts
        findings.group_by(&:severity)
                .sort_by { |severity, _| -Severity.rank(severity) }
                .to_h { |severity, list| [severity, list.size] }
      end

      def worst_severity = findings.first&.severity

      def clean? = failed.empty?

      # 0 clean, 1 findings at or above +fail_on+, 2 a check errored. Errors
      # outrank findings: a run that could not complete should not report
      # success, whatever it managed to check.
      def exit_status(fail_on: nil)
        return 2 if errored.any?
        return 0 if fail_on.nil? ? clean? : findings(min_severity: fail_on).empty?

        1
      end

      def to_h
        {
          'summary' => {
            'checks'     => results.size,
            'passed'     => passed.size,
            'failed'     => failed.size,
            'skipped'    => skipped.size,
            'errored'    => errored.size,
            'suppressed' => suppressed,
            'findings'   => counts.transform_keys(&:to_s)
          },
          'results' => results.map(&:to_h)
        }
      end
    end
  end
end
