module UiManage
  module Audit
    # How bad a finding is, ordered least to most severe.
    module Severity
      ORDER = %i[info low medium high critical].freeze

      module_function

      def valid?(name) = ORDER.include?(normalize(name))

      def normalize(name) = name.to_s.downcase.to_sym

      # Position in ORDER, for comparing two severities.
      def rank(name)
        ORDER.index(normalize(name)) ||
          raise(ArgumentError, "Unknown severity #{name.inspect} — use one of #{ORDER.join(', ')}.")
      end

      def at_or_above?(name, floor) = rank(name) >= rank(floor)

      # Severities from +floor+ up, most severe first — the order findings
      # should be read in.
      def from(floor) = ORDER[rank(floor)..].reverse
    end
  end
end
