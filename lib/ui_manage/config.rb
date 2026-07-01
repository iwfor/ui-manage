require 'toml-rb'
require 'fileutils'

module UiManage
  class Config
    CONFIG_DIR  = File.join(Dir.home, '.config', 'ui-manage')
    CONFIG_FILE = File.join(CONFIG_DIR, 'config.toml')

    def initialize
      FileUtils.mkdir_p(CONFIG_DIR)
      Encryption.ensure_key
      @data = load_file
    end

    def default_device_name
      @data.dig('settings', 'default_device')
    end

    def devices
      @data['devices'] || []
    end

    def device(name = nil)
      name ||= default_device_name
      return devices.first if name.nil?

      devices.find { |d| d['name'] == name } ||
        raise("Device '#{name}' not found. Run `ui-manage devices` to list configured devices.")
    end

    def add_device(name:, host:, site: 'default', username: nil, encrypted_password: nil, encrypted_api_key: nil)
      @data['devices'] ||= []
      @data['devices'].reject! { |d| d['name'] == name }

      entry = { 'name' => name, 'host' => host, 'site' => site }
      if encrypted_api_key
        entry['encrypted_api_key'] = encrypted_api_key
      else
        entry['username']           = username
        entry['encrypted_password'] = encrypted_password
      end
      @data['devices'] << entry

      if @data['devices'].length == 1
        @data['settings'] ||= {}
        @data['settings']['default_device'] = name
      end

      save
    end

    def set_default(name)
      device(name) # raises if not found
      @data['settings'] ||= {}
      @data['settings']['default_device'] = name
      save
    end

    def remove_device(name)
      @data['devices']&.reject! { |d| d['name'] == name }
      if default_device_name == name
        @data['settings']['default_device'] = devices.first&.dig('name')
      end
      save
    end

    private

    def load_file
      return {} unless File.exist?(CONFIG_FILE)

      TomlRB.load_file(CONFIG_FILE)
    rescue => e
      abort "Error loading config (#{CONFIG_FILE}): #{e.message}"
    end

    def save
      File.write(CONFIG_FILE, serialize)
      File.chmod(0o600, CONFIG_FILE)
    end

    def serialize
      lines = []

      if (settings = @data['settings'])
        printable = settings.reject { |_, v| v.nil? }
        unless printable.empty?
          lines << '[settings]'
          printable.each { |k, v| lines << "#{k} = #{toml_val(v)}" }
          lines << ''
        end
      end

      (@data['devices'] || []).each do |d|
        lines << '[[devices]]'
        d.each { |k, v| lines << "#{k} = #{toml_val(v)}" }
        lines << ''
      end

      lines.join("\n")
    end

    def toml_val(v)
      case v
      when String  then v.inspect
      when Integer then v.to_s
      when Float   then v.to_s
      when true, false then v.to_s
      else v.inspect
      end
    end
  end
end
