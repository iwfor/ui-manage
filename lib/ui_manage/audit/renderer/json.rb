module UiManage
  module Audit
    class Renderer
      # Machine-readable output, for feeding another tool or diffing runs.
      class Json < Renderer
        def render
          payload = {
            'summary'     => summary.merge('by_severity' => counts),
            'findings'    => findings.map { |f| finding_hash(f) },
            'not_checked' => (report.skipped + report.errored).map do |result|
              { 'check' => result.check.id.to_s, 'status' => result.status.to_s,
                'reason' => result.reason }
            end
          }
          payload['resolved'] = resolved if resolved.any?
          payload['passed']   = report.passed.map { |r| r.check.id.to_s } if show_passing?

          # Findings carry controller data, so they go through the same
          # redaction as every other JSON path in the tool.
          JSON.pretty_generate(Redactor.scrub(payload)) + "\n"
        end

        private

        def finding_hash(finding)
          hash = finding.to_h
          hash['message'] = scrub(hash['message'])
          hash['subject'] = subject_of(finding) unless finding.subject.nil?
          hash.delete('remediation') unless remediate?
          hash
        end
      end
    end
  end
end
