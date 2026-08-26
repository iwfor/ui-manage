require_relative '../test_helper'

module UiManage
  module Audit
    class RunnerTest < TestCase
      # A check defined for one test only. Registry registers every subclass,
      # so these are built inside an isolated registry rather than the real
      # one (see #with_isolated_registry).
      def build_check(id:, category: :security, severity: :high, requires: [], &body)
        Class.new(Check) do
          id id
          title "check #{id}"
          category category
          severity severity
          requires(*requires) unless requires.empty?
          define_method(:run, &body)
        end
      end

      # Registry is global by design — a check file registers itself on load.
      # Tests that define their own checks swap it out and put it back.
      def with_isolated_registry
        saved_checks = Registry.checks.dup
        saved_loaded = Registry.instance_variable_get(:@loaded)
        Registry.reset!
        yield
      ensure
        Registry.instance_variable_set(:@checks, saved_checks)
        Registry.instance_variable_set(:@loaded, saved_loaded)
      end

      def context(routes = {}, **options)
        routes, options = split_routes(routes, options)
        device   = options.fetch(:device, {})
        settings = options[:settings]
        client = Client.new(host: 'unifi.test', api_key: 'k', transport: stub_transport(routes))
        Context.new(client: client, device: device, settings: settings || Settings.new(path: nil))
      end

      def run_checks(checks, ctx)
        Runner.new(context: ctx, checks: checks).run
      end

      # --- outcomes -------------------------------------------------------

      def test_a_check_that_finds_nothing_passes
        with_isolated_registry do
          check  = build_check(id: :quiet) { nil }
          report = run_checks([check], context)

          assert_equal 1, report.passed.size
          assert report.clean?
        end
      end

      def test_a_check_that_reports_something_fails
        with_isolated_registry do
          check  = build_check(id: :noisy) { finding(message: 'wrong', subject: 'thing') }
          report = run_checks([check], context)

          assert_equal 1, report.failed.size
          assert_equal 'wrong', report.findings.first.message
          refute report.clean?
        end
      end

      # The point of the whole degradation path: a check whose data the
      # controller would not serve must be reported as not-checked, never as
      # a pass.
      def test_a_check_whose_endpoint_is_refused_is_skipped_with_the_reason
        with_isolated_registry do
          check  = build_check(id: :needs_wlans, requires: [:wlans]) { finding(message: 'never runs') }
          report = run_checks([check], context({ 'wlanconf' => 403 }))

          assert_equal 1, report.skipped.size
          assert_empty report.passed
          assert_includes report.skipped.first.reason, 'not permitted'
        end
      end

      def test_a_skipped_check_never_runs_its_body
        with_isolated_registry do
          ran   = false
          check = build_check(id: :needs_wlans, requires: [:wlans]) { ran = true }
          run_checks([check], context({ 'wlanconf' => 404 }))

          refute ran
        end
      end

      def test_a_check_can_skip_itself_when_the_data_does_not_say_enough
        with_isolated_registry do
          check  = build_check(id: :undecidable) { skip!('the controller does not report it') }
          report = run_checks([check], context)

          assert_equal 1, report.skipped.size
          assert_includes report.skipped.first.reason, 'does not report'
        end
      end

      # A bug in one check must not end the audit, and must not be mistaken
      # for a clean result.
      def test_a_check_that_raises_is_recorded_as_an_error_and_the_run_continues
        with_isolated_registry do
          broken  = build_check(id: :broken) { raise 'kaboom' }
          working = build_check(id: :working) { finding(message: 'found it') }
          report  = run_checks([broken, working], context)

          assert_equal 1, report.errored.size
          assert_includes report.errored.first.reason, 'kaboom'
          assert_equal 1, report.failed.size
          assert_empty report.passed
        end
      end

      # --- suppression ------------------------------------------------------

      def test_a_suppressed_finding_is_dropped_and_counted
        with_isolated_registry do
          check = build_check(id: :noisy) do
            finding(message: 'accepted', subject: 'Guest')
            finding(message: 'real', subject: 'Home')
          end
          settings = Settings.new(path: nil, suppressed_findings: ['noisy:Guest'])
          report   = run_checks([check], context(settings: settings))

          assert_equal 1, report.suppressed
          assert_equal ['Home'], report.findings.map(&:subject)
        end
      end

      def test_a_check_whose_every_finding_is_suppressed_passes
        with_isolated_registry do
          check    = build_check(id: :noisy) { finding(message: 'accepted', subject: 'Guest') }
          settings = Settings.new(path: nil, suppressed_findings: ['noisy:Guest'])
          report   = run_checks([check], context(settings: settings))

          assert_equal 1, report.passed.size
          assert report.clean?
        end
      end

      # --- report ----------------------------------------------------------

      def test_findings_are_ordered_most_severe_first
        with_isolated_registry do
          check = build_check(id: :mixed) do
            finding(message: 'a', subject: 'x', severity: :low)
            finding(message: 'b', subject: 'y', severity: :critical)
            finding(message: 'c', subject: 'z', severity: :medium)
          end
          report = run_checks([check], context)

          assert_equal %i[critical medium low], report.findings.map(&:severity)
          assert_equal :critical, report.worst_severity
        end
      end

      def test_findings_can_be_filtered_by_severity
        with_isolated_registry do
          check = build_check(id: :mixed) do
            finding(message: 'a', subject: 'x', severity: :low)
            finding(message: 'b', subject: 'y', severity: :critical)
          end
          report = run_checks([check], context)

          assert_equal 1, report.findings(min_severity: :high).size
        end
      end

      def test_counts_summarise_by_severity
        with_isolated_registry do
          check = build_check(id: :mixed) do
            finding(message: 'a', subject: 'x', severity: :high)
            finding(message: 'b', subject: 'y', severity: :high)
            finding(message: 'c', subject: 'z', severity: :low)
          end

          assert_equal({ high: 2, low: 1 }, run_checks([check], context).counts)
        end
      end

      # --- exit status ------------------------------------------------------

      def test_a_clean_run_exits_zero
        with_isolated_registry do
          assert_equal 0, run_checks([build_check(id: :quiet) { nil }], context).exit_status
        end
      end

      def test_findings_at_or_above_the_threshold_exit_one
        with_isolated_registry do
          check  = build_check(id: :noisy) { finding(message: 'x', severity: :medium) }
          report = run_checks([check], context)

          assert_equal 1, report.exit_status(fail_on: :medium)
          assert_equal 0, report.exit_status(fail_on: :high)
          assert_equal 1, report.exit_status
        end
      end

      # A run that could not complete must not report success, whatever else
      # it managed to check.
      def test_an_errored_check_exits_two_regardless_of_the_threshold
        with_isolated_registry do
          report = run_checks([build_check(id: :broken) { raise 'boom' }], context)

          assert_equal 2, report.exit_status(fail_on: :critical)
        end
      end

      # A skip is not a failure, but it is also not a silent pass — it has to
      # remain visible in the summary.
      def test_skipped_checks_do_not_fail_the_run_but_stay_visible
        with_isolated_registry do
          check  = build_check(id: :needs_wlans, requires: [:wlans]) { finding(message: 'x') }
          report = run_checks([check], context({ 'wlanconf' => 403 }))

          assert_equal 0, report.exit_status
          assert_equal 1, report.to_h['summary']['skipped']
        end
      end
    end
  end
end
