module UiManage
  module Audit
    class Renderer
      # For pasting into a ticket, a wiki, or a message to whoever has to act
      # on it.
      class Markdown < Renderer
        def render
          out = ["# Network audit", '', summary_table]
          out += ['', findings_sections] unless summary_only? || findings.empty?
          out += ['', resolved_section] if resolved.any?
          out += ['', not_checked_section] if report.skipped.any? || report.errored.any?
          out.join("\n").rstrip + "\n"
        end

        private

        def summary_table
          s     = summary
          rows  = [['Checks run', s['checks']], ['Passed', s['passed']],
                   ['With findings', s['failed']], ['Not checked', s['skipped']],
                   ['Errored', s['errored']]]
          rows << ['Suppressed', s['suppressed']] if s['suppressed'].positive?

          lines = ['| | |', '| --- | --- |']
          lines += rows.map { |label, value| "| #{label} | #{value} |" }
          lines += counts.map { |severity, n| "| **#{severity.capitalize}** | #{n} |" }
          lines.join("\n")
        end

        def findings_sections
          findings.group_by(&:severity).map do |severity, group|
            body = group.map { |finding| finding_block(finding) }.join("\n\n")
            "## #{severity.to_s.capitalize} (#{group.size})\n\n#{body}"
          end.join("\n\n")
        end

        def finding_block(finding)
          lines = ["- **#{scrub(finding.message)}**"]
          lines << "  - Check: `#{finding.check_id}`"
          lines << "  - Subject: `#{subject_of(finding)}`" unless finding.subject.nil?
          lines << "  - Fix: #{finding.remediation}" if remediate? && finding.remediation
          lines.join("\n")
        end

        # Deliberately its own section rather than folded into the summary:
        # a reader must not mistake "could not check" for "checked and fine".
        def not_checked_section
          lines = ['## Not checked', '',
                   'These checks could not run. They are not passes.', '']
          lines += report.skipped.map { |r| "- `#{r.check.id}` — #{r.reason}" }
          lines += report.errored.map { |r| "- `#{r.check.id}` — **errored**: #{r.reason}" }
          lines.join("\n")
        end

        def resolved_section
          (['## Resolved since the baseline', ''] + resolved.map { |key| "- `#{key}`" }).join("\n")
        end
      end
    end
  end
end
