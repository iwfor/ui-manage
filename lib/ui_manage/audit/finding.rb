module UiManage
  module Audit
    # One thing wrong, on one subject.
    #
    # +subject+ names what the finding is about — an SSID, a device, a rule —
    # so findings can be suppressed individually and grouped in output.
    # +evidence+ carries the values the check actually read, so a reader can
    # confirm the finding without re-running anything.
    class Finding
      attr_reader :check_id, :severity, :subject, :message, :evidence, :remediation

      def initialize(check_id:, severity:, message:, subject: nil, evidence: nil, remediation: nil)
        @check_id    = check_id
        @severity    = Severity.normalize(severity)
        @subject     = subject
        @message     = message
        @evidence    = evidence
        @remediation = remediation
      end

      # Identifies this finding for suppression: the check alone when it has
      # no subject, or "check:subject" when it does.
      def key = subject.nil? ? check_id.to_s : "#{check_id}:#{subject}"

      def to_h
        {
          'check'       => check_id.to_s,
          'severity'    => severity.to_s,
          'subject'     => subject,
          'message'     => message,
          'evidence'    => evidence,
          'remediation' => remediation
        }.compact
      end
    end
  end
end
