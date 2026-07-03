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

    def self.generate(shell, prog:, commands:)
      unless SHELLS.include?(shell)
        raise ArgumentError, "Unsupported shell: #{shell.inspect} (expected #{SHELLS.join(' or ')})"
      end

      bash = bash_script(prog, commands)
      return bash if shell == 'bash'

      "autoload -Uz bashcompinit && bashcompinit\n#{bash}"
    end

    def self.bash_script(prog, commands)
      func          = "_#{prog.gsub(/[^a-zA-Z0-9_]/, '_')}_completions"
      command_names = commands.keys.sort.join(' ')
      case_clauses  = commands.sort.map { |name, flags| "    #{name}) opts=\"#{flags.sort.join(' ')}\" ;;" }.join("\n")

      <<~BASH
        #{func}() {
          local cur cmd opts
          COMPREPLY=()
          cur="${COMP_WORDS[COMP_CWORD]}"
          cmd="${COMP_WORDS[1]}"

          if [ "$COMP_CWORD" -le 1 ]; then
            COMPREPLY=( $(compgen -W "#{command_names}" -- "$cur") )
            return 0
          fi

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
  end
end
