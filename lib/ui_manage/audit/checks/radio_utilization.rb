module UiManage
  module Audit
    module Checks
      # How much of the air is already busy. Unlike signal strength this
      # counts everyone's traffic, including networks that are not yours —
      # which is why a client can show full bars and still crawl.
      class RadioUtilization < Check
        id          :radio_utilization
        title       'Radio channel utilization above threshold'
        category    :health
        severity    :medium
        requires    :devices
        remediation 'Move to a quieter channel, narrow the channel width, or reduce ' \
                    'transmit power so cells overlap less. Adjust the bar with ' \
                    'channel_util_percent in audit.toml.'

        UTILIZATION_KEYS = %w[cu_total channel_utilization cu_self_rx].freeze

        def run
          limit  = threshold('channel_util_percent')
          radios = data(:devices).flat_map do |device|
            next [] unless DeviceState.connected?(device)

            Array(device['radio_table_stats']).filter_map do |radio|
              value = UTILIZATION_KEYS.filter_map { |k| radio[k] }.first
              next if value.nil?

              [device, radio, value.to_f]
            end
          end

          skip!('no radio reports channel utilization') if radios.empty?

          radios.each do |device, radio, utilization|
            next if utilization <= limit

            name = device['name'] || device['mac']
            finding(
              subject:  "#{name}:#{radio['radio']}",
              message:  "#{name} #{band_name(radio['radio'])} is #{utilization.round}% utilized " \
                        "on channel #{radio['channel']}, above the #{limit}% threshold.",
              evidence: { 'utilization_percent' => utilization.round(1), 'threshold' => limit,
                          'channel' => radio['channel'] }
            )
          end
        end

        private

        def band_name(band) = { 'ng' => '2.4 GHz', 'na' => '5 GHz', '6e' => '6 GHz' }.fetch(band.to_s, band.to_s)
      end
    end
  end
end
