module UiManage
  module Audit
    class Renderer
      # Terminal output: a summary line, then findings grouped by severity,
      # then what could not be checked.
      class Table < Renderer
        SEVERITY_COLOUR = {
          critical: :bright_red, high: :red, medium: :yellow, low: :cyan, info: :dim
        }.freeze

        def render
          sections = [headline]
          sections << findings_section unless summary_only? || findings.empty?
          sections << resolved_section if resolved.any?
          sections << not_checked_section if report.skipped.any? || report.errored.any?
          sections << passing_section if show_passing? && report.passed.any?
          sections.compact.join("\n") + "\n"
        end

        private

        def headline
          s     = summary
          tally = counts.map { |severity, n| colour(severity, "#{n} #{severity}") }.join(', ')
          lines = ["#{s['checks']} checks: #{s['passed']} passed, #{s['failed']} with findings, " \
                   "#{s['skipped']} not checked, #{s['errored']} errored"]
          lines << (findings.empty? ? 'No findings.' : "Findings: #{tally}")
          lines << "#{s['suppressed']} finding(s) suppressed by audit.toml." if s['suppressed'].positive?
          lines.join("\n") + "\n"
        end

        def findings_section
          out = ["Findings\n" + ('=' * 70)]

          findings.group_by(&:severity).each do |severity, group|
            out << "\n#{colour(severity, severity.to_s.upcase)} (#{group.size})\n" + ('-' * 70)
            group.each { |finding| out << finding_lines(finding) }
          end
          out.join("\n") + "\n"
        end

        def finding_lines(finding)
          head  = ["  #{scrub(finding.message)}"]
          head << "    check:   #{finding.check_id}"
          head << "    subject: #{subject_of(finding)}" unless finding.subject.nil?
          head << "    fix:     #{finding.remediation}" if remediate? && finding.remediation
          head.join("\n")
        end

        # Kept visually distinct from findings: these are things the audit did
        # not establish, not things it found to be fine.
        def not_checked_section
          out = ["Not checked\n" + ('=' * 70)]
          report.skipped.each { |r| out << "  #{r.check.id}: #{r.reason}" }
          report.errored.each { |r| out << "  #{r.check.id}: ERRORED — #{r.reason}" }
          out.join("\n") + "\n"
        end

        def resolved_section
          out = ["Resolved since the baseline\n" + ('=' * 70)]
          resolved.each { |key| out << "  #{key}" }
          out.join("\n") + "\n"
        end

        def passing_section
          out = ["Passed\n" + ('=' * 70)]
          report.passed.each { |r| out << "  #{r.check.id}: #{r.check.title}" }
          out.join("\n") + "\n"
        end

        def colour(severity, text)
          @pastel.decorate(text, SEVERITY_COLOUR.fetch(severity.to_sym, :white))
        end
      end
    end
  end
end
