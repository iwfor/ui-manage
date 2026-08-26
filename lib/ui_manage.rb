module UiManage
  # Overridable so tests (and anyone keeping more than one profile) can point
  # at a different directory without touching the real one. Both the config
  # and the encryption key live here, and both are created 0600 inside a 0700
  # directory.
  CONFIG_DIR =
    if (dir = ENV['UI_MANAGE_CONFIG_DIR']) && !dir.strip.empty?
      File.expand_path(dir)
    else
      File.join(Dir.home, '.config', 'ui-manage')
    end
end

require_relative 'ui_manage/encryption'
require_relative 'ui_manage/config'
require_relative 'ui_manage/transport'
require_relative 'ui_manage/client'
require_relative 'ui_manage/formatter'
require_relative 'ui_manage/anonymizer'
require_relative 'ui_manage/completions'
require_relative 'ui_manage/cli'
