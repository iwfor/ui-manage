module UiManage
  module Audit
    # What running one check produced.
    #
    # Four states, not two. `skipped` and `errored` mean different things and
    # must not be conflated: a skip is expected — the controller or credential
    # would not provide the data, which Phase 1 already records a reason for —
    # while an error is a bug in the check. Reporting a skip as a pass would
    # be the worst outcome of all, since "not checked" would read as "fine".
    class Result
      STATUSES = %i[pass fail skip error].freeze

      attr_reader :check, :status, :findings, :reason

      def initialize(check:, status:, findings: [], reason: nil)
        raise ArgumentError, "Unknown status #{status.inspect}" unless STATUSES.include?(status)

        @check    = check
        @status   = status
        @findings = findings
        @reason   = reason
      end

      def self.pass(check)                 = new(check: check, status: :pass)
      def self.fail(check, findings)       = new(check: check, status: :fail, findings: findings)
      def self.skip(check, reason)         = new(check: check, status: :skip, reason: reason)
      def self.error(check, reason)        = new(check: check, status: :error, reason: reason)

      def passed?  = status == :pass
      def failed?  = status == :fail
      def skipped? = status == :skip
      def errored? = status == :error

      # The worst severity among this result's findings, or nil.
      def severity
        findings.map(&:severity).max_by { |s| Severity.rank(s) }
      end

      def to_h
        {
          'check'    => check.id.to_s,
          'title'    => check.title,
          'category' => check.category.to_s,
          'status'   => status.to_s,
          'reason'   => reason,
          'findings' => findings.map(&:to_h)
        }.compact
      end
    end
  end
end
