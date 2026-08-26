module UiManage
  # Generates a shell completion script for the CLI's subcommands and their
  # option flags, introspected from the Thor command definitions so the
  # completions can't drift out of sync with the actual commands.
  #
  # Zsh reuses the bash script via `bashcompinit` instead of a parallel
  # `_arguments` spec, keeping a single source of truth for the completion
  # logic.
  module Completions
    SHELLS = %w[bash zsh].freeze

    # +values+ maps a flag to the set of values it accepts (check ids,
    # severities, formats), so those complete to the real thing rather than to
    # nothing.
    def self.generate(shell, prog:, commands:, values: {})
      unless SHELLS.include?(shell)
        raise ArgumentError, "Unsupported shell: #{shell.inspect} (expected #{SHELLS.join(' or ')})"
      end

      bash = bash_script(prog, commands, values)
      return bash if shell == 'bash'

      "autoload -Uz bashcompinit && bashcompinit\n#{bash}"
    end

    def self.bash_script(prog, commands, values = {})
      func          = "_#{prog.gsub(/[^a-zA-Z0-9_]/, '_')}_completions"
      command_names = commands.keys.sort.join(' ')
      case_clauses  = commands.sort.map { |name, flags| "    #{name}) opts=\"#{flags.sort.join(' ')}\" ;;" }.join("\n")

      <<~BASH
        #{func}() {
          local cur prev cmd opts
          COMPREPLY=()
          cur="${COMP_WORDS[COMP_CWORD]}"
          prev="${COMP_WORDS[COMP_CWORD-1]}"
          cmd="${COMP_WORDS[1]}"

          if [ "$COMP_CWORD" -le 1 ]; then
            COMPREPLY=( $(compgen -W "#{command_names}" -- "$cur") )
            return 0
          fi
        #{value_case(values)}
          case "$cmd" in
        #{case_clauses}
            *) opts="" ;;
          esac

          COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
        }
        complete -F #{func} #{prog}
      BASH
    end
    private_class_method :bash_script

    # Completes the value after a flag that takes one from a known set. Checked
    # before the per-command flag list, so `--severity <tab>` offers severities
    # rather than more flag names.
    def self.value_case(values)
      return '' if values.empty?

      clauses = values.sort.map do |flag, allowed|
        "    #{flag})\n" \
        "      COMPREPLY=( $(compgen -W \"#{Array(allowed).sort.join(' ')}\" -- \"$cur\") )\n" \
        '      return 0 ;;'
      end.join("\n")

      "\n  case \"$prev\" in\n#{clauses}\n  esac\n"
    end
    private_class_method :value_case
  end
end
