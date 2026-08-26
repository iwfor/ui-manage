require 'json'
require 'pastel'

module UiManage
  module Audit
    # Turns a Report into text. Each format is a subclass implementing #render;
    # everything they share — ordering, grouping, counts — lives here.
    class Renderer
      FORMATS = %w[table json markdown html].freeze

      def self.for(format)
        case format.to_s
        when 'table'    then Table
        when 'json'     then Json
        when 'markdown' then Markdown
        when 'html'     then Html
        else raise ArgumentError, "Unknown format #{format.inspect} — use #{FORMATS.join(', ')}."
        end
      end

      def self.render(report, format: 'table', **options)
        self.for(format).new(report, **options).render
      end

      attr_reader :report, :options

      def initialize(report, min_severity: nil, show_passing: false, summary_only: false,
                     remediate: false, anon: nil, colour: false, resolved: [])
        @report       = report
        @min_severity = min_severity
        @show_passing = show_passing
        @summary_only = summary_only
        @remediate    = remediate
        @anon         = anon || Anonymizer.new(false)
        @resolved     = resolved
        @pastel       = Pastel.new(enabled: colour)
      end

      def render = raise(NotImplementedError)

      private

      attr_reader :anon, :resolved

      def findings
        @findings ||= begin
          list = report.findings(min_severity: @min_severity)
          # Every subject is registered before any message is scrubbed, so a
          # message naming an SSID or a device is anonymised to the same
          # placeholder as the column that names it.
          list.each { |finding| anon.label(finding.subject) }
          list
        end
      end

      def summary_only? = @summary_only

      def remediate? = @remediate

      def show_passing? = @show_passing

      def summary
        s = report.to_h['summary']
        {
          'checks' => s['checks'], 'passed' => s['passed'], 'failed' => s['failed'],
          'skipped' => s['skipped'], 'errored' => s['errored'], 'suppressed' => s['suppressed'],
          'findings' => findings.size
        }
      end

      def counts
        findings.group_by(&:severity)
                .sort_by { |severity, _| -Severity.rank(severity) }
                .to_h { |severity, list| [severity.to_s, list.size] }
      end

      # Findings carry free text and identifiers from the controller, so both
      # go through the anonymizer when one is active.
      def scrub(text) = anon.scrub(text.to_s)

      def subject_of(finding) = finding.subject.nil? ? '' : anon.label(finding.subject).to_s
    end
  end
end

require_relative 'renderer/table'
require_relative 'renderer/json'
require_relative 'renderer/markdown'
require_relative 'renderer/html'
