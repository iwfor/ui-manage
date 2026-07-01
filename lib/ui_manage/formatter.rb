require 'terminal-table'
require 'json'

module UiManage
  module Formatter
    def self.json(data)
      puts JSON.pretty_generate(data)
    end

    def self.table(headings, rows, title: nil)
      t = Terminal::Table.new(
        title:    title,
        headings: headings,
        rows:     rows
      )
      t.style = { border_x: '-', border_y: '|', border_i: '+' }
      puts t
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
