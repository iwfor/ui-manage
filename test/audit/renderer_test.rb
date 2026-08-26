require_relative '../test_helper'

module UiManage
  module Audit
    class RendererTest < TestCase
      def check = Registry.find(:wlan_encryption)

      def finding(**args)
        Finding.new(**{ check_id: :wlan_encryption, severity: :critical, subject: 'Guest',
                        message: 'Guest uses no encryption.',
                        remediation: 'Set WPA2 or WPA3.' }.merge(args))
      end

      def report(findings: [finding], skipped: [], errored: [], passed: [])
        results = []
        results << Result.fail(check, findings) if findings.any?
        results += Array(passed).map { |c| Result.pass(c) }
        results += Array(skipped).map { |(c, reason)| Result.skip(c, reason) }
        results += Array(errored).map { |(c, reason)| Result.error(c, reason) }
        Report.new(results: results)
      end

      def render(format, **options) = Renderer.render(report(**options.delete(:report) || {}), format: format, **options)

      # --- format selection --------------------------------------------------

      def test_every_declared_format_renders
        Renderer::FORMATS.each do |format|
          output = Renderer.render(report, format: format)

          refute_empty output, "#{format} rendered nothing"
          assert_includes output, 'Guest', "#{format} lost the finding"
        end
      end

      def test_an_unknown_format_is_rejected
        assert_raises(ArgumentError) { Renderer.render(report, format: 'pdf') }
      end

      # --- what must never be lost -------------------------------------------

      # A reader skimming any format must not mistake "could not check" for
      # "checked and fine".
      def test_every_format_distinguishes_not_checked_from_passed
        skipped = report(skipped: [[Registry.find(:admin_two_factor), 'the credential cannot read admins']])

        Renderer::FORMATS.each do |format|
          output = Renderer.render(skipped, format: format)

          assert_match(/not.checked/i, output, "#{format} does not say the check was skipped")
          assert_includes output, 'cannot read admins', "#{format} drops the reason"
        end
      end

      def test_every_format_reports_an_errored_check
        errored = report(findings: [], errored: [[check, 'NoMethodError: boom']])

        Renderer::FORMATS.each do |format|
          output = Renderer.render(errored, format: format)

          assert_match(/error/i, output, "#{format} hides the errored check")
        end
      end

      # --- table -------------------------------------------------------------

      def test_the_table_groups_findings_by_severity
        mixed = report(findings: [finding(severity: :low, subject: 'A', message: 'minor'),
                                  finding(severity: :critical, subject: 'B', message: 'severe')])
        output = Renderer.render(mixed, format: 'table')

        assert output.index('CRITICAL') < output.index('LOW')
      end

      def test_the_table_reports_a_clean_run_plainly
        output = Renderer.render(report(findings: []), format: 'table')

        assert_includes output, 'No findings.'
      end

      def test_remediation_is_off_by_default_and_shown_on_request
        refute_includes Renderer.render(report, format: 'table'), 'Set WPA2'
        assert_includes Renderer.render(report, format: 'table', remediate: true), 'Set WPA2'
      end

      def test_summary_only_omits_individual_findings
        output = Renderer.render(report, format: 'table', summary_only: true)

        refute_includes output, 'Guest uses no encryption'
        assert_includes output, 'Findings:'
      end

      def test_passing_checks_are_listed_on_request
        passing = report(findings: [], passed: [check])

        refute_includes Renderer.render(passing, format: 'table'), 'wlan_encryption'
        assert_includes Renderer.render(passing, format: 'table', show_passing: true), 'wlan_encryption'
      end

      def test_severity_filtering_narrows_the_findings
        mixed  = report(findings: [finding(severity: :low, subject: 'A', message: 'minor'),
                                   finding(severity: :critical, subject: 'B', message: 'severe')])
        output = Renderer.render(mixed, format: 'table', min_severity: :high)

        assert_includes output, 'severe'
        refute_includes output, 'minor'
      end

      # --- json --------------------------------------------------------------

      def test_json_is_parseable_and_carries_the_summary
        parsed = JSON.parse(Renderer.render(report, format: 'json'))

        assert_equal 1, parsed['summary']['findings']
        assert_equal 'wlan_encryption', parsed['findings'].first['check']
        assert_equal 'critical', parsed['findings'].first['severity']
      end

      def test_json_lists_what_could_not_be_checked
        skipped = report(skipped: [[Registry.find(:admin_two_factor), 'no permission']])
        parsed  = JSON.parse(Renderer.render(skipped, format: 'json'))

        assert_equal 'skip', parsed['not_checked'].first['status']
      end

      # Findings carry controller data, so they go through the same redaction
      # as every other JSON path in the tool.
      def test_json_findings_are_redacted
        secret = report(findings: [finding(evidence: { 'x_passphrase' => 'hunter2' })])
        output = Renderer.render(secret, format: 'json')

        refute_includes output, 'hunter2'
        assert_includes output, Redactor::PLACEHOLDER
      end

      # --- anonymisation -----------------------------------------------------

      def test_anonymising_scrubs_addresses_out_of_finding_text
        addressed = report(findings: [finding(message: 'Host 192.168.1.50 is exposed', subject: '192.168.1.50')])

        Renderer::FORMATS.each do |format|
          output = Renderer.render(addressed, format: format, anon: Anonymizer.new(true))

          refute_includes output, '192.168.1.50', "#{format} leaked the address"
        end
      end

      # --- html --------------------------------------------------------------

      def test_the_html_page_is_self_contained
        output = Renderer.render(report, format: 'html')

        assert_includes output, '<!doctype html>'
        assert_includes output, '<style>'
        refute_match(%r{<(script|link|img)\b}, output)
        refute_includes output, 'http://'
      end

      def test_html_escapes_finding_text
        injected = report(findings: [finding(message: '<script>alert(1)</script>')])
        output   = Renderer.render(injected, format: 'html')

        refute_includes output, '<script>alert(1)</script>'
        assert_includes output, '&lt;script&gt;'
      end

      # --- markdown ----------------------------------------------------------

      def test_markdown_has_a_summary_table_and_severity_headings
        output = Renderer.render(report, format: 'markdown')

        assert_includes output, '| --- | --- |'
        assert_includes output, '## Critical (1)'
      end
    end

    class BaselineTest < TestCase
      def path = File.join(TEST_CONFIG_DIR, 'baseline.json')

      def teardown = FileUtils.rm_f(path)

      def finding(subject)
        Finding.new(check_id: :wlan_encryption, severity: :high, subject: subject, message: 'x')
      end

      def test_a_baseline_round_trips
        Baseline.new(keys: ['wlan_encryption:Guest']).save(path)

        assert_equal ['wlan_encryption:Guest'], Baseline.load(path).keys
      end

      def test_only_findings_absent_from_the_baseline_are_new
        baseline = Baseline.new(keys: ['wlan_encryption:Guest'])
        current  = [finding('Guest'), finding('IoT')]

        assert_equal ['IoT'], baseline.new_findings(current).map(&:subject)
      end

      # Worth saying out loud: a scheduled audit that only ever reports new
      # problems never tells you anything got better.
      def test_findings_gone_since_the_baseline_are_reported_as_resolved
        baseline = Baseline.new(keys: ['wlan_encryption:Guest', 'wlan_encryption:Old'])

        assert_equal ['wlan_encryption:Old'], baseline.resolved([finding('Guest')])
      end

      def test_a_missing_baseline_says_how_to_make_one
        error = assert_raises(ArgumentError) { Baseline.load(File.join(TEST_CONFIG_DIR, 'nope.json')) }

        assert_includes error.message, '--save-baseline'
      end

      def test_a_baseline_from_a_future_format_is_refused_rather_than_misread
        File.write(path, JSON.generate('format' => 99, 'findings' => []))

        assert_raises(ArgumentError) { Baseline.load(path) }
      end

      def test_a_corrupt_baseline_is_reported_clearly
        File.write(path, 'not json')

        assert_raises(ArgumentError) { Baseline.load(path) }
      end
    end
  end
end
