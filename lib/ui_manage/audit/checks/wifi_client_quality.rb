module UiManage
  module Audit
    module Checks
      # Wireless clients that are connected but having a bad time — too far
      # from an access point, or retransmitting a large share of what they
      # send. Both read to the user as "the wifi is slow" rather than as a
      # failure.
      class WifiClientQuality < Check
        id          :wifi_client_quality
        title       'Wireless clients with weak signal or high retry rate'
        category    :health
        severity    :medium
        requires    :clients
        remediation 'Move or add an access point, or lower the minimum RSSI so weak ' \
                    'clients roam instead of clinging. Adjust with min_rssi_dbm and ' \
                    'max_retry_percent in audit.toml.'

        def run
          floor      = threshold('min_rssi_dbm')
          max_retry  = threshold('max_retry_percent')
          wireless   = data(:clients).reject { |c| c['is_wired'] }

          weak = wireless.select { |c| c['signal'] && c['signal'].to_i < floor }
          report_group(weak, 'signal',
                       "below #{floor} dBm",
                       ->(c) { "#{c['signal']} dBm" })

          retrying = wireless.select { |c| retry_percent(c) && retry_percent(c) > max_retry }
          report_group(retrying, 'retries',
                       "above a #{max_retry}% transmit retry rate",
                       ->(c) { "#{retry_percent(c).round(1)}%" })
        end

        private

        # Grouped into one finding per problem rather than one per client: on
        # a busy network the individual clients change constantly, and the
        # actionable fact is how many there are.
        def report_group(clients, subject, description, formatter)
          return if clients.empty?

          named = clients.first(10).map do |client|
            "#{client['name'] || client['hostname'] || client['mac']} (#{formatter.call(client)})"
          end

          finding(
            subject:  subject,
            message:  "#{clients.size} wireless client#{'s' if clients.size != 1} " \
                      "#{clients.size == 1 ? 'is' : 'are'} #{description}.",
            evidence: { 'count' => clients.size, 'clients' => named }
          )
        end

        def retry_percent(client)
          attempts = client['wifi_tx_attempts'].to_i
          return nil if attempts.zero?

          client['wifi_tx_retries'].to_i.to_f / attempts * 100
        end
      end
    end
  end
end
