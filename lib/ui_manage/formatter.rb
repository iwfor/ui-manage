require 'terminal-table'
require 'json'

module UiManage
  module Formatter
    def self.json(data)
      puts JSON.pretty_generate(data)
    end

    def self.table(headings, rows, title: nil, sort: nil)
      rows = sort_rows(headings, rows, sort) if sort && !rows.empty?

      t = Terminal::Table.new(
        title:    title,
        headings: headings,
        rows:     rows
      )
      t.style = { border_x: '-', border_y: '|', border_i: '+' }
      puts t
    end

    # Sorts +rows+ by the column in +headings+ that matches +sort+: an exact
    # (case-insensitive) column name, or a fragment unique to one column.
    def self.sort_rows(headings, rows, sort)
      idx = sort_column_index(headings, sort)
      rows.sort_by { |row| sort_key(row[idx]) }
    end

    def self.sort_column_index(headings, sort)
      names  = headings.map(&:to_s)
      needle = sort.downcase

      exact = names.index { |h| h.downcase == needle }
      return exact if exact

      matches = names.each_index.select { |i| !names[i].empty? && names[i].downcase.include?(needle) }
      case matches.size
      when 0
        abort "ERROR: no column matches #{sort.inspect}. Available columns: #{names.reject(&:empty?).join(', ')}"
      when 1
        matches.first
      else
        abort "ERROR: #{sort.inspect} matches multiple columns (#{matches.map { |i| names[i] }.join(', ')}) " \
              '— use a more specific name.'
      end
    end

    # Numbers sort numerically and before text; everything else sorts as
    # case-insensitive text. Multi-line cells sort on their first line.
    def self.sort_key(val)
      str = val.to_s
      str = str.lines.first.to_s.chomp if str.include?("\n")

      /\A-?\d+(\.\d+)?\z/.match?(str) ? [0, str.to_f] : [1, str.downcase]
    end

    def self.kv(pairs, title: nil)
      puts title if title
      max = pairs.map { |k, _| k.to_s.length }.max || 0
      pairs.each do |k, v|
        printf "  %-#{max}s  %s\n", k, v
      end
    end

    def self.section(label)
      puts "\n#{label}"
      puts '-' * label.length
    end

    def self.enabled_badge(val)
      val ? 'YES' : 'no'
    end

    def self.bytes_human(bytes)
      return 'N/A' unless bytes
      bytes = bytes.to_i
      units = %w[B KB MB GB TB]
      exp   = (Math.log(bytes) / Math.log(1024)).floor
      exp   = [exp, units.length - 1].min
      format('%.1f %s', bytes.to_f / (1024**exp), units[exp])
    end

    def self.percent(used, total)
      return 'N/A' unless used && total && total.to_f > 0

      pct = (used.to_f / total.to_f * 100).round(1)
      "#{pct}%"
    end
  end
end
