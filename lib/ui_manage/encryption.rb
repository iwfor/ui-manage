require 'openssl'
require 'base64'
require 'securerandom'
require 'fileutils'

module UiManage
  module Encryption
    KEY_FILE = File.join(CONFIG_DIR, 'secret.key')

    def self.ensure_key
      FileUtils.mkdir_p(CONFIG_DIR, mode: 0o700)
      File.chmod(0o700, CONFIG_DIR)
      return if File.exist?(KEY_FILE)

      # Created 0600 atomically — writing first and chmodding after would leave
      # a window where the key is readable under the default umask.
      key = SecureRandom.bytes(32)
      File.open(KEY_FILE, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |f|
        f.binmode
        f.write(key)
      end
      warn "Generated new encryption key at #{KEY_FILE}"
    rescue Errno::EEXIST
      # Another process created the key between the exist? check and open.
    end

    def self.key
      ensure_key
      File.binread(KEY_FILE)
    end

    def self.encrypt(plaintext)
      c         = cipher(:encrypt)
      iv        = c.random_iv
      encrypted = c.update(plaintext.to_s) + c.final
      Base64.strict_encode64(iv + c.auth_tag + encrypted)
    end

    def self.decrypt(ciphertext)
      raw = Base64.strict_decode64(ciphertext)
      # 12-byte IV + 16-byte GCM tag; anything shorter is corrupt.
      raise ArgumentError, 'Corrupt encrypted value in config' if raw.bytesize < 28

      c          = cipher(:decrypt)
      c.iv       = raw[0, 12]
      c.auth_tag = raw[12, 16]
      c.update(raw[28..]) + c.final
    end

    def self.cipher(mode)
      c = OpenSSL::Cipher.new('aes-256-gcm')
      c.public_send(mode)
      c.key = key
      c
    end
    private_class_method :cipher
  end
end
