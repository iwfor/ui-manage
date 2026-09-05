module UiManage
  module Audit
    module Checks
      # Attacks the gateway has actually seen recently. Unlike the
      # configuration checks, this one reports something that already
      # happened.
      class IpsDetections < Check
        id          :ips_recent_detections
        title       'Recent intrusion detections'
        category    :security
        severity    :high
        requires    :ips_events
        remediation 'Review under Insights > Threat Management. Recurring detections ' \
                    'against one internal host usually mean that host, not the ' \
                    'perimeter, is the problem.'

        def run
          events = data(:ips_events)
          return if events.empty?

          by_signature = events.group_by { |e| SystemLog.title(e) || 'unknown' }

          by_signature.each do |signature, matches|
            worst = matches.map { |e| SystemLog.rank(e) }.max

            # Endpoint addresses are read from the legacy field names. No
            # system-log SECURITY entry has been seen on a real controller
            # yet, so which parameter carries them there is not known.
            finding(
              subject:  signature,
              severity: worst >= SystemLog::RANKS['high'] ? :high : :medium,
              message:  "#{matches.size} detection#{'s' if matches.size != 1} of " \
                        "'#{signature}' in the last 24 hours.",
              evidence: { 'count' => matches.size,
                          'sources' => matches.filter_map { |e| e['src_ip'] || e['srcip'] }.uniq.first(5),
                          'destinations' => matches.filter_map { |e| e['dest_ip'] || e['dstip'] }.uniq.first(5) }
            )
          end
        end
      end
    end
  end
end
