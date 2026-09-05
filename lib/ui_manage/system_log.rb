require 'time'

module UiManage
  # Reading entries from the controller's system log.
  #
  # Network application 9 replaced /stat/event, /stat/alarm, and
  # /stat/ips/event with one paged v2 endpoint, system-log/all, whose entries
  # carry a message *template* ("{CLIENT} connected to {WLAN}") plus a
  # parameters hash to fill it from. Alarms are the entries at warning
  # severity and above; IDS/IPS detections are the SECURITY category.
  #
  # Client still falls back to the legacy endpoints on an older controller,
  # so every reader here understands both shapes: a view or check never has
  # to know which one it was handed.
  module SystemLog
    # Filters system-log/all accepts, as the controller names them.
    CATEGORIES = %w[SECURITY UNIFI_DEVICES SOFTWARE_UPDATES VPN POWER UNIFI_ETHERNET_PORTS
                    CLIENT_DEVICES UNKNOWN AUDIT INTERNET_AND_WAN].freeze
    SEVERITIES = %w[INFO LOW MEDIUM WARNING HIGH VERY_HIGH].freeze

    # What the legacy endpoints used to select.
    ALARM_SEVERITIES  = %w[WARNING HIGH VERY_HIGH].freeze
    THREAT_CATEGORIES = %w[SECURITY].freeze

    # The three-step scale the CLI filters on. Controller severities map onto
    # it; legacy IPS entries carry a Suricata number, where 1 is most severe.
    RANKS      = { 'low' => 1, 'medium' => 2, 'high' => 3 }.freeze
    V2_RANKS   = { 'INFO' => 1, 'LOW' => 1, 'MEDIUM' => 2, 'WARNING' => 2, 'HIGH' => 3, 'VERY_HIGH' => 3 }.freeze
    IPS_LABELS = { 3 => 'low', 2 => 'medium', 1 => 'high' }.freeze

    module_function

    def v2?(entry) = entry.key?('message_raw') || entry.key?('timestamp')

    # Entries carry an epoch `timestamp` (v2) or `time` (legacy) in
    # milliseconds, or a preformatted `datetime`.
    def time(entry)
      if (ms = entry['timestamp'] || entry['time'])
        Time.at(ms.to_i / 1000)
      elsif (dt = entry['datetime'])
        Time.iso8601(dt.to_s) rescue nil
      end
    end

    def category(entry)
      entry['subcategory'] || entry['catname'] || entry['inner_alert_category'] || entry['category'] || entry['subsystem']
    end

    def key(entry) = entry['key']

    # What the entry is about, as a short name: the v2 title, the IPS
    # signature that fired, or failing both the event key.
    def title(entry)
      return fill(entry['title_raw'], entry) if entry['title_raw']

      entry['inner_alert_signature'] || entry['key']
    end

    # The human-readable message.
    def message(entry)
      entry['message_raw'] ? fill(entry['message_raw'], entry) : entry['msg'].to_s
    end

    # Fills each {PARAMETER} in a v2 template from the entry's parameters
    # hash. A placeholder with no parameter is left as it is, so the gap is
    # visible rather than silently closed up.
    def fill(template, entry)
      params = entry['parameters'] || {}
      template.gsub(/\{([A-Z0-9_]+)\}/) { parameter_text(params[Regexp.last_match(1)]) || Regexp.last_match(0) }
    end

    # 'low', 'medium', 'high', or nil when the entry carries no severity.
    # v2 names are mapped rather than passed through so `--severity high`
    # means one thing on every controller.
    def severity(entry)
      if (raw = entry['severity'])
        RANKS.key(V2_RANKS[raw.to_s.upcase]) || raw.to_s.downcase
      elsif (ips = entry['inner_alert_severity'])
        IPS_LABELS[ips.to_i]
      end
    end

    # 0 for an entry with no severity, so it never survives a `--severity`
    # filter — an unknown level is not evidence of a low one.
    def rank(entry) = RANKS.fetch(severity(entry).to_s, 0)

    def archived?(entry)
      return !!entry['archived'] if entry.key?('archived')

      entry['status'].to_s.casecmp?('ARCHIVED')
    end

    # A parameter is a hash naming one thing ({name, id}) or a list of them
    # ({clients: [...]}, {devices: [...]}).
    def parameter_text(param)
      case param
      when Hash
        return param['name'] || param['id'] if param['name'] || param['id']

        list = param.values.find { |v| v.is_a?(Array) }
        list && list.filter_map { |item| parameter_text(item) }.join(', ')
      when Array then param.filter_map { |item| parameter_text(item) }.join(', ')
      when nil then nil
      else param.to_s
      end
    end
  end
end
