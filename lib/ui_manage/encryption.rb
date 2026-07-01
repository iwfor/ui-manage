require 'openssl'
require 'base64'
require 'securerandom'
require 'fileutils'

module UiManage
  module Encryption
    CONFIG_DIR = File.join(Dir.home, '.config', 'ui-manage')
    KEY_FILE   = File.join(CONFIG_DIR, 'secret.key')

    def self.ensure_key
      FileUtils.mkdir_p(CONFIG_DIR)
      return if File.exist?(KEY_FILE)

      key = SecureRandom.bytes(32)
      File.binwrite(KEY_FILE, key)
      File.chmod(0o600, KEY_FILE)
      warn "Generated new encryption key at #{KEY_FILE}"
    end

    def self.key
      ensure_key
      File.binread(KEY_FILE)
    end

    def self.encrypt(plaintext)
      cipher = OpenSSL::Cipher.new('aes-256-gcm')
      cipher.encrypt
      cipher.key = key
      iv        = cipher.random_iv
      encrypted = cipher.update(plaintext.to_s) + cipher.final
      tag       = cipher.auth_tag
      Base64.strict_encode64(iv + tag + encrypted)
    end

    def self.decrypt(ciphertext)
      raw       = Base64.strict_decode64(ciphertext)
      iv        = raw[0, 12]
      tag       = raw[12, 16]
      encrypted = raw[28..]

      cipher = OpenSSL::Cipher.new('aes-256-gcm')
      cipher.decrypt
      cipher.key     = key
      cipher.iv      = iv
      cipher.auth_tag = tag
      cipher.update(encrypted) + cipher.final
    end
  end
end
