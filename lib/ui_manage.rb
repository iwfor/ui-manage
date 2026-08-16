module UiManage
  CONFIG_DIR = File.join(Dir.home, '.config', 'ui-manage')
end

require_relative 'ui_manage/encryption'
require_relative 'ui_manage/config'
require_relative 'ui_manage/client'
require_relative 'ui_manage/formatter'
require_relative 'ui_manage/anonymizer'
require_relative 'ui_manage/completions'
require_relative 'ui_manage/cli'
