module UiManage
  module Audit
    module Checks
      # PoE draw approaching what the switch can supply. Crossing the budget
      # does not fail gracefully: the switch drops power to ports by priority,
      # so the symptom is an access point going dark rather than an error.
      class PoeBudget < Check
        id          :poe_budget
        title       'PoE draw approaching the switch budget'
        category    :health
        severity    :high
        requires    :devices
        remediation 'Move a device to another switch, or fit a higher-budget switch. ' \
                    'Adjust the bar with poe_budget_percent in audit.toml.'

        BUDGET_KEYS = %w[total_max_power poe_max_power max_power].freeze

        def run
          limit    = threshold('poe_budget_percent')
          devices  = data(:devices)
          budgeted = devices.select { |d| budget(d).positive? }

          skip!('no device reports a PoE budget') if budgeted.empty?

          budgeted.each do |device|
            total   = budget(device)
            draw    = Array(device['port_table']).sum { |p| p['poe_power'].to_f }
            percent = draw / total * 100
            next if percent <= limit

            finding(
              subject:  device['name'] || device['mac'],
              message:  "#{device['name'] || device['model']} is drawing #{draw.round(1)}W of " \
                        "#{total.round(1)}W (#{percent.round(1)}%), above the #{limit}% threshold.",
              evidence: { 'draw_watts' => draw.round(1), 'budget_watts' => total.round(1),
                          'percent' => percent.round(1), 'threshold' => limit }
            )
          end
        end

        private

        def budget(device)
          BUDGET_KEYS.filter_map { |k| device[k]&.to_f }.max || 0.0
        end
      end
    end
  end
end
