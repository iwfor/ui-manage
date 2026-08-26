require 'json'
require 'time'

module UiManage
  module Audit
    # A snapshot of what a previous run found, so a later run can report only
    # what changed.
    #
    # This is what makes the audit usable on a schedule. A full report is
    # worth reading once; on the tenth run, the only interesting part is what
    # is new — and what has been fixed, which is worth saying out loud.
    class Baseline
      FORMAT = 1

      attr_reader :keys, :recorded_at

      def initialize(keys: [], recorded_at: nil)
        @keys        = keys.map(&:to_s)
        @recorded_at = recorded_at
      end

      def self.from_report(report)
        new(keys: report.findings.map(&:key), recorded_at: Time.now.utc.iso8601)
      end

      def self.load(path)
        raw = JSON.parse(File.read(path))
        unless raw['format'] == FORMAT
          raise ArgumentError, "#{path} is not a baseline this version understands (format #{raw['format'].inspect})."
        end

        new(keys: Array(raw['findings']), recorded_at: raw['recorded_at'])
      rescue Errno::ENOENT
        raise ArgumentError, "No baseline at #{path}. Write one with --save-baseline."
      rescue JSON::ParserError => e
        raise ArgumentError, "Could not read baseline #{path}: #{e.message}"
      end

      def save(path)
        File.write(path, JSON.pretty_generate(
          'format'      => FORMAT,
          'recorded_at' => recorded_at || Time.now.utc.iso8601,
          'findings'    => keys.sort
        ) + "\n")
        path
      end

      # Findings not present in the baseline.
      def new_findings(findings) = findings.reject { |f| keys.include?(f.key) }

      # Baseline entries that no longer appear — fixed since the snapshot.
      def resolved(findings)
        current = findings.map(&:key)
        (keys - current).sort
      end
    end
  end
end
