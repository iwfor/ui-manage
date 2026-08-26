module UiManage
  module Audit
    module Checks
      # Latency and loss on the uplink, as the controller measures it.
      class WanLatency < Check
        id          :wan_latency
        title       'Internet uplink latency or loss above threshold'
        category    :health
        severity    :high
        requires    :health
        remediation 'Compare against the ISP\'s own figures before escalating; a single ' \
                    'high reading is often the controller\'s probe rather than the line. ' \
                    'Adjust with wan_latency_ms and wan_loss_percent in audit.toml.'

        def run
          wan = data(:health).find { |h| h['subsystem'].to_s == 'wan' }
          skip!('the controller reports no WAN health subsystem') if wan.nil?

          check_latency(wan)
          check_loss(wan)
        end

        private

        def check_latency(wan)
          limit   = threshold('wan_latency_ms')
          latency = wan['latency']
          return if latency.nil? || latency.to_f <= limit

          finding(
            severity: :high,
            subject:  'latency',
            message:  "Uplink latency is #{latency}ms, above the #{limit}ms threshold.",
            evidence: { 'latency_ms' => latency.to_f, 'threshold' => limit }
          )
        end

        def check_loss(wan)
          limit = threshold('wan_loss_percent')
          # The controller reports loss only on some versions; absence is not
          # zero loss, so it is left alone rather than reported as healthy.
          loss = wan['drops'] || wan['loss']
          return if loss.nil? || loss.to_f <= limit

          finding(
            severity: :high,
            subject:  'loss',
            message:  "Uplink packet loss is #{loss}%, above the #{limit}% threshold.",
            evidence: { 'loss_percent' => loss.to_f, 'threshold' => limit }
          )
        end
      end
    end
  end
end
