require 'toml-rb'

module UiManage
  class Config
    CONFIG_FILE = File.join(CONFIG_DIR, 'config.toml')

    # Per-device audit policy: what this network's owner considers correct,
    # which the audit compares the controller's actual state against. Stored
    # with the device because the answer differs per site — remote access is
    # a finding on one network and a requirement on the next.
    POLICY_KEYS = %w[remote_access_expected].freeze

    def initialize
      Encryption.ensure_key # also creates CONFIG_DIR
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

    def add_device(name:, host:, site: 'default', username: nil, encrypted_password: nil,
                   encrypted_api_key: nil, verify_ssl: false, remote_access_expected: nil)
      { 'name' => name, 'host' => host, 'site' => site, 'username' => username }.each do |field, value|
        validate_field!(field, value)
      end

      @data['devices'] ||= []
      previous = @data['devices'].find { |d| d['name'] == name }
      @data['devices'].reject! { |d| d['name'] == name }

      entry = { 'name' => name, 'host' => host, 'site' => site, 'verify_ssl' => verify_ssl }
      if encrypted_api_key
        entry['encrypted_api_key'] = encrypted_api_key
      else
        entry['username']           = username
        entry['encrypted_password'] = encrypted_password
      end

      # An unanswered policy question keeps whatever the device already had,
      # so re-running `login` to rotate a credential doesn't silently reset it.
      policy = remote_access_expected.nil? ? previous&.dig('remote_access_expected') : !!remote_access_expected
      entry['remote_access_expected'] = policy unless policy.nil?

      @data['devices'] << entry

      if @data['devices'].length == 1
        @data['settings'] ||= {}
        @data['settings']['default_device'] = name
      end

      save
    end

    # Updates audit policy on an existing device. Only POLICY_KEYS may be set
    # this way — credentials and connection details go through add_device, so
    # they are never changed without re-authenticating.
    def update_device_policy(name, **attrs)
      unknown = attrs.keys.map(&:to_s) - POLICY_KEYS
      raise ArgumentError, "Unknown policy setting(s): #{unknown.join(', ')}" if unknown.any?

      dev = device(name)
      attrs.each do |key, value|
        if value.nil?
          dev.delete(key.to_s)
        else
          dev[key.to_s] = !!value
        end
      end
      save
      dev
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

    # toml-rb (parser and dumper alike, as of 3.0.1) mishandles control
    # characters in strings, producing a config file that can't be re-read.
    # Reject them at the boundary rather than corrupting the config.
    def validate_field!(field, value)
      return if value.nil?

      if value.to_s.match?(/[\x00-\x1f\x7f]/)
        raise ArgumentError, "Device #{field} must not contain control characters"
      end
    end

    def load_file
      return {} unless File.exist?(CONFIG_FILE)

      TomlRB.load_file(CONFIG_FILE)
    rescue => e
      abort "Error loading config (#{CONFIG_FILE}): #{e.message}"
    end

    # The file is created 0600 via open's permission argument (chmodding after
    # writing would leave a readable window under the default umask); the
    # explicit chmod fixes up files created before that was the case.
    def save
      File.open(CONFIG_FILE, File::WRONLY | File::CREAT | File::TRUNC, 0o600) do |f|
        f.write(serialize)
      end
      File.chmod(0o600, CONFIG_FILE)
    end

    def serialize
      data = @data.dup
      if (settings = data['settings'])
        printable = settings.reject { |_, v| v.nil? }
        printable.empty? ? data.delete('settings') : data['settings'] = printable
      end
      TomlRB.dump(data)
    end
  end
end
