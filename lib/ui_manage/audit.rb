module UiManage
  # The audit engine: checks, the data they read, and the run that turns them
  # into findings.
  #
  # The engine is deliberately separate from the checks themselves — adding a
  # check means adding one file under audit/checks/, with no other wiring.
  module Audit
  end
end

require_relative 'audit/severity'
require_relative 'audit/finding'
require_relative 'audit/result'
require_relative 'audit/registry'
require_relative 'audit/check'
require_relative 'audit/settings'
require_relative 'audit/context'
require_relative 'audit/report'
require_relative 'audit/runner'
