module UiManage
  module Audit
    module Checks
      # An uplink that is down, or a secondary uplink carrying traffic because
      # the primary failed. Failover working is good; failover working
      # unnoticed for weeks is not.
      class WanStatus < Check
        id          :wan_status
        title       'Internet uplink down or running on failover'
        category    :health
        severity    :critical
        requires    :devices
        remediation 'Check the uplink under Internet in UniFi Network, then the modem ' \
                    'or fibre terminal upstream of it.'

        def run
          device = gateway
          skip!('no gateway device was found') if device.nil?

          uplinks = %w[wan1 wan2].filter_map do |key|
            wan = device[key]
            [key, wan] if wan.is_a?(Hash) && !wan.empty?
          end
          skip!('this device reports no WAN information') if uplinks.empty?

          enabled = uplinks.select { |_, wan| wan['enable'] != false }

          enabled.each do |key, wan|
            next if wan['up']

            finding(
              subject:  wan['name'] || key,
              message:  "#{wan['name'] || key} is down.",
              evidence: { 'interface' => wan['ifname'], 'type' => wan['type'] }
            )
          end

          report_failover(enabled)
        end

        private

        # Running on the secondary while the primary is down is already
        # reported above; this catches the case where the primary is up but
        # the secondary is the one carrying traffic.
        def report_failover(uplinks)
          return unless uplinks.size > 1

          primary, secondary = uplinks.first(2).map(&:last)
          return unless primary['up'] && secondary['up']
          return unless secondary['is_uplink'] && !primary['is_uplink']

          finding(
            severity: :high,
            subject:  secondary['name'] || 'wan2',
            message:  'Traffic is running over the secondary uplink while the primary is up.',
            evidence: { 'active' => secondary['name'], 'primary_up' => true }
          )
        end
      end
    end
  end
end
