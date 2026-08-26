require_relative 'test_helper'

module UiManage
  # `report` runs every view outside its own command, where that command's
  # options are not in scope — the case most likely to break as views are
  # added, and the one a real controller would expose only at runtime.
  class ReportTest < TestCase
    def report_output(routes = {})
      render(:report, routes)
    end

    def test_a_report_covers_every_section
      out = report_output

      ['Identity', 'Health', 'CPU', 'Memory', 'Storage', 'Firmware', 'Gateway (WAN)',
       'Clients', 'Wireless Experience', 'WLANs', 'Neighbouring Access Points',
       'Networks / VLANs', 'VPN', 'Firewall Rules', 'Port Forwards',
       'Routes & Dynamic DNS', 'DHCP Networks', 'Power (PoE)', 'Ports',
       'Port Errors', 'Administrators', 'Site Settings', 'Alarms',
       'IDS/IPS Detections'].each do |section|
        assert_includes out, section, "report is missing the #{section} section"
      end
    end

    # A credential that cannot read the optional endpoints — an API key, in
    # practice — must still get a complete report.
    def test_a_report_survives_every_optional_endpoint_being_refused
      routes = %w[wlanconf get/setting stat/health rogueap sitemgr
                  stat/alarm ips/event rest/routing dynamicdns].to_h { |p| [p, 403] }
      out    = report_output(routes)

      assert_includes out, 'unavailable'
      assert_includes out, 'IDS/IPS Detections'
      refute_includes out, 'No administrators reported'
    end

    def test_windowed_sections_use_the_documented_default_outside_their_command
      out = report_output

      assert_includes out, 'last 24h'
    end

    def test_a_report_never_prints_a_secret
      routes = {
        'wlanconf'     => [{ 'name' => 'Home', 'security' => 'wpapsk', 'x_passphrase' => 'hunter2psk' }],
        'get/setting'  => [{ 'key' => 'mgmt', 'x_ssh_password' => 'sshsecret' }],
        'networkconf'  => [{ 'name' => 'VPN', 'purpose' => 'site-vpn',
                             'x_ipsec_pre_shared_key' => 'ipsecsecret' }]
      }
      out = report_output(routes)

      refute_includes out, 'hunter2psk'
      refute_includes out, 'sshsecret'
      refute_includes out, 'ipsecsecret'
    end
  end
end
