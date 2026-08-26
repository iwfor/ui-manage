require_relative 'test_helper'

module UiManage
  # The audit command end to end: flags, exit statuses, and output routing.
  class AuditCommandTest < TestCase
    UNHEALTHY = {
      'wlanconf'    => [{ 'name' => 'Guest', 'enabled' => true, 'security' => 'open' }],
      'stat/device' => [{ 'name' => 'AP', 'state' => 0, 'model' => 'U6' }],
      'get/setting' => 403,
      'sitemgr'     => 403
    }.freeze

    # Runs `audit` and returns [stdout, exit status]. The command exits, so the
    # status is captured rather than allowed to end the test run.
    def run_audit(routes = {}, *args, **options)
      render_with_status(:audit, routes, args: args, **options)
    end

    # --- catalogue (no controller needed) -----------------------------------

    def test_list_checks_needs_no_controller
      out, = run_audit({}, list_checks: true)

      assert_includes out, 'Audit checks'
      assert_includes out, 'wlan_encryption'
    end

    def test_explain_describes_one_check
      out, = run_audit({}, explain: 'wlan_passphrase')

      assert_includes out, 'min_passphrase_chars'
      assert_includes out, 'not-checked rather than as a pass'
    end

    def test_explaining_an_unknown_check_says_how_to_find_the_ids
      assert_aborts('--list-checks') { invoke(:audit, {}, explain: 'no_such_check') }
    end

    # --- exit status --------------------------------------------------------

    def test_a_clean_run_exits_zero
      _, status = run_audit({ 'stat/device' => [{ 'name' => 'AP', 'state' => 1 }] },
                            check: ['device_offline'])

      assert_equal 0, status
    end

    def test_findings_exit_one
      _, status = run_audit(UNHEALTHY, check: ['device_offline'])

      assert_equal 1, status
    end

    def test_fail_on_sets_the_bar_for_a_nonzero_exit
      _, below = run_audit(UNHEALTHY, check: ['firewall_unused_group'], fail_on: 'high')
      _, above = run_audit(UNHEALTHY, check: ['device_offline'], fail_on: 'high')

      assert_equal 0, below
      assert_equal 1, above
    end

    # --- filtering ----------------------------------------------------------

    def test_a_category_narrows_the_run
      out, = run_audit(UNHEALTHY, 'security')

      assert_includes out, 'wlan_encryption'
      refute_includes out, 'device_offline'
    end

    def test_an_unknown_category_is_rejected
      assert_raises(Thor::Error) { invoke(:audit, UNHEALTHY, args: ['nonsense']) }
    end

    def test_checks_can_be_selected_by_glob
      out, = run_audit(UNHEALTHY, check: ['wlan_*'], all: true)

      assert_includes out, 'wlan_encryption'
      refute_includes out, 'device_offline'
    end

    def test_checks_can_be_excluded
      out, = run_audit(UNHEALTHY, skip: ['device_*'])

      refute_includes out, 'device_offline'
    end

    def test_filters_matching_nothing_are_reported
      assert_aborts('No checks match') { invoke(:audit, UNHEALTHY, check: ['no_such_*']) }
    end

    def test_an_unknown_severity_is_rejected
      assert_raises(Thor::Error) { invoke(:audit, UNHEALTHY, severity: 'urgent') }
      assert_raises(Thor::Error) { invoke(:audit, UNHEALTHY, fail_on: 'urgent') }
    end

    # --- output -------------------------------------------------------------

    def test_the_format_can_be_chosen
      json, = run_audit(UNHEALTHY, check: ['device_offline'], format: 'json')

      assert_equal 'device_offline', JSON.parse(json)['findings'].first['check']
    end

    def test_the_json_flag_is_shorthand_for_the_json_format
      out, = run_audit(UNHEALTHY, check: ['device_offline'], json: true)

      assert JSON.parse(out)
    end

    def test_an_unknown_format_is_rejected
      assert_raises(Thor::Error) { invoke(:audit, UNHEALTHY, format: 'pdf') }
    end

    def test_output_can_be_written_to_a_file
      path = File.join(TEST_CONFIG_DIR, 'audit.html')
      out, = run_audit(UNHEALTHY, check: ['device_offline'], format: 'html', output: path)

      assert_includes out, "Wrote #{path}"
      assert_includes File.read(path), '<!doctype html>'
    ensure
      FileUtils.rm_f(path)
    end

    # --- degradation --------------------------------------------------------

    # The whole point of the skip machinery, seen from the command line: a
    # credential that cannot read a section must not produce a clean bill.
    def test_checks_that_could_not_run_are_reported_separately_from_passes
      out, status = run_audit(UNHEALTHY, check: ['admin_two_factor'])

      assert_includes out, 'Not checked'
      assert_includes out, 'admin_two_factor'
      assert_equal 0, status
      assert_includes out, '1 not checked'
    end

    # --- baseline -----------------------------------------------------------

    def test_a_baseline_narrows_a_later_run_to_what_is_new
      path = File.join(TEST_CONFIG_DIR, 'baseline.json')
      run_audit(UNHEALTHY, check: ['device_offline'], save_baseline: path)

      out, status = run_audit(UNHEALTHY, check: ['device_offline'], baseline: path)

      refute_includes out, 'AP-Garage'
      assert_includes out, 'No findings.'
      assert_equal 0, status
    ensure
      FileUtils.rm_f(path)
    end

    def test_a_baseline_reports_what_has_since_been_fixed
      path = File.join(TEST_CONFIG_DIR, 'baseline.json')
      run_audit(UNHEALTHY, check: ['device_offline'], save_baseline: path)

      healthy = { 'stat/device' => [{ 'name' => 'AP', 'state' => 1 }] }
      out, = run_audit(healthy, check: ['device_offline'], baseline: path)

      assert_includes out, 'Resolved since the baseline'
      assert_includes out, 'device_offline:AP'
    ensure
      FileUtils.rm_f(path)
    end

    def test_a_new_finding_still_surfaces_against_a_baseline
      path = File.join(TEST_CONFIG_DIR, 'baseline.json')
      run_audit({ 'stat/device' => [{ 'name' => 'AP', 'state' => 1 }] },
                check: ['device_offline'], save_baseline: path)

      out, status = run_audit(UNHEALTHY, check: ['device_offline'], baseline: path)

      assert_includes out, 'AP is disconnected'
      assert_equal 1, status
    ensure
      FileUtils.rm_f(path)
    end

    def test_a_missing_baseline_file_is_reported
      assert_aborts('--save-baseline') do
        invoke(:audit, UNHEALTHY, baseline: File.join(TEST_CONFIG_DIR, 'absent.json'))
      end
    end
  end
end
