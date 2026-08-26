module UiManage
  # Matching for the port specifications UniFi stores on forwarding rules,
  # which may be a single port ("22"), a range ("8000-8010"), or a comma
  # separated list of either ("80,443,8000-8010").
  module PortSpec
    module_function

    # Every port a spec covers, as an array. Ranges wider than +cap+ are
    # summarised rather than expanded, so a rule forwarding all 65535 ports
    # cannot turn into a 65535-element array.
    def ranges(spec)
      spec.to_s.split(',').filter_map do |part|
        part = part.strip
        next if part.empty?

        low, _, high = part.partition('-')
        next if low.empty?

        (low.to_i..(high.empty? ? low : high).to_i)
      end
    end

    def include?(spec, port)
      ranges(spec).any? { |r| r.cover?(port) }
    end

    # Which of +ports+ the spec covers.
    def intersection(spec, ports)
      Array(ports).select { |p| include?(spec, p.to_i) }
    end

    def any?(spec) = ranges(spec).any?
  end
end
