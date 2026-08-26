require_relative 'test_helper'

module UiManage
  class CLITest < TestCase
    def cli(**options)
      CLI.new([], Thor::CoreExt::HashWithIndifferentAccess.new(options))
    end

    # --- policy labels --------------------------------------------------------

    def test_policy_labels_distinguish_unset_from_a_deliberate_no
      assert_equal 'expected',     cli.send(:policy_label, true)
      assert_equal 'not expected', cli.send(:policy_label, false)
      assert_equal 'unset',        cli.send(:policy_label, nil)
    end

    # --- remote access prompt -------------------------------------------------

    def test_an_explicit_flag_is_taken_without_prompting
      assert_equal true,  cli(remote_access: true).send(:remote_access_policy)
      assert_equal false, cli(remote_access: false).send(:remote_access_policy)
    end

    def test_a_non_interactive_run_leaves_the_policy_unset_and_says_so
      result = nil
      out, = capture_io { result = with_stdin(tty: false) { cli.send(:remote_access_policy) } }

      assert_nil result
      assert_includes out, 'ui-manage policy'
    end

    def test_an_interactive_run_asks_and_takes_the_answer
      [true, false].each do |answer|
        shell = interactive_cli(answer: answer)
        result = nil
        capture_io { result = with_stdin(tty: true) { shell.send(:remote_access_policy) } }

        assert_equal answer, result
        assert_includes shell.asked.to_s, 'Remote access expected'
      end
    end

    def test_an_explicit_flag_wins_over_the_prompt
      shell = interactive_cli(answer: true, remote_access: false)
      result = with_stdin(tty: true) { shell.send(:remote_access_policy) }

      assert_equal false, result
      assert_nil shell.asked
    end

    def test_the_prompt_explains_what_the_answer_is_used_for
      shell = interactive_cli(answer: false)
      out, = capture_io { with_stdin(tty: true) { shell.send(:remote_access_policy) } }

      assert_includes out, 'remote (cloud) access'
      assert_includes out, 'audit'
    end

    # --- api key validation ---------------------------------------------------

    def test_an_api_key_with_control_characters_is_rejected
      assert_aborts('control characters') do
        cli.send(:read_api_key, "key\nproxy = http://attacker.test")
      end
    end

    def test_an_ordinary_api_key_passes_through
      assert_equal 'abc123', cli.send(:read_api_key, 'abc123')
    end

    private

    # Thor's `yes?` reaches for a real line editor as soon as stdin looks like a
    # terminal, so the question itself is stubbed and only the gate around it is
    # exercised with a fake stdin.
    def interactive_cli(answer:, **options)
      shell = cli(**options)
      shell.define_singleton_method(:yes?) { |question| @asked = question; answer }
      shell.define_singleton_method(:asked) { @asked }
      shell
    end

    # Only the tty check matters here — it is what decides whether the
    # prompt is offered at all.
    def with_stdin(tty:)
      original = $stdin
      $stdin   = StringIO.new
      $stdin.define_singleton_method(:tty?) { tty }
      yield
    ensure
      $stdin = original
    end
  end
end
