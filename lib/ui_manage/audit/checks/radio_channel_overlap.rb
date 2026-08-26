module UiManage
  module Audit
    module Checks
      # Two of this site's own access points sharing a channel within range of
      # each other. They then take turns transmitting rather than working in
      # parallel, which halves throughput for both while every signal meter
      # still reads full.
      class RadioChannelOverlap < Check
        id          :radio_channel_overlap
        title       'Access points sharing a channel'
        category    :health
        severity    :medium
        requires    :devices
        remediation 'Settings > WiFi > Radios: let the controller pick channels, or on ' \
                    '2.4 GHz assign 1, 6, and 11 by hand — they are the only three that ' \
                    'do not overlap.'

        # 2.4 GHz channels sit 5 MHz apart but are 20 MHz wide, so anything
        # closer than five channels apart interferes.
        ADJACENT_SPACING = 5

        def run
          radios = data(:devices).flat_map do |device|
            next [] unless DeviceState.connected?(device)

            Array(device['radio_table_stats'] || device['radio_table']).filter_map do |radio|
              channel = radio['channel'].to_i
              next if channel.zero?

              { device: device['name'] || device['mac'], radio: radio['radio'].to_s, channel: channel }
            end
          end

          radios.group_by { |r| r[:radio] }.each do |band, on_band|
            next if on_band.size < 2

            on_band.combination(2).each do |first, second|
              next if first[:device] == second[:device]

              distance = (first[:channel] - second[:channel]).abs
              next unless overlapping?(band, distance)

              report(band, first, second, distance)
            end
          end
        end

        private

        # Only 2.4 GHz has the adjacent-channel problem; 5 and 6 GHz channels
        # are allocated so that different numbers do not overlap.
        def overlapping?(band, distance)
          return distance.zero? unless band == 'ng'

          distance < ADJACENT_SPACING
        end

        def report(band, first, second, distance)
          same = distance.zero?
          finding(
            subject:  "#{first[:device]} / #{second[:device]}",
            severity: same ? :medium : :low,
            message:  "#{first[:device]} and #{second[:device]} are on " \
                      "#{same ? "the same channel (#{first[:channel]})" :
                                "overlapping channels (#{first[:channel]} and #{second[:channel]})"} " \
                      "on #{band_name(band)}.",
            evidence: { 'channels' => [first[:channel], second[:channel]], 'band' => band_name(band) }
          )
        end

        def band_name(band) = { 'ng' => '2.4 GHz', 'na' => '5 GHz', '6e' => '6 GHz' }.fetch(band, band)
      end
    end
  end
end
