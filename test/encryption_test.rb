require_relative 'test_helper'

module UiManage
  class EncryptionTest < TestCase
    def test_a_secret_survives_a_round_trip
      assert_equal 'hunter2', Encryption.decrypt(Encryption.encrypt('hunter2'))
    end

    def test_an_empty_secret_round_trips
      assert_equal '', Encryption.decrypt(Encryption.encrypt(''))
    end

    def test_a_multibyte_secret_round_trips
      secret = 'påsswörd–✓'

      assert_equal secret, Encryption.decrypt(Encryption.encrypt(secret)).force_encoding('UTF-8')
    end

    def test_the_same_plaintext_encrypts_differently_each_time
      refute_equal Encryption.encrypt('same'), Encryption.encrypt('same')
    end

    def test_a_tampered_ciphertext_is_rejected_rather_than_decrypted
      raw = Base64.strict_decode64(Encryption.encrypt('hunter2'))
      raw.setbyte(raw.bytesize - 1, raw.getbyte(raw.bytesize - 1) ^ 0xFF)

      assert_raises(OpenSSL::Cipher::CipherError) { Encryption.decrypt(Base64.strict_encode64(raw)) }
    end

    def test_a_tampered_auth_tag_is_rejected
      raw = Base64.strict_decode64(Encryption.encrypt('hunter2'))
      raw.setbyte(13, raw.getbyte(13) ^ 0xFF)

      assert_raises(OpenSSL::Cipher::CipherError) { Encryption.decrypt(Base64.strict_encode64(raw)) }
    end

    def test_a_truncated_value_is_reported_as_corrupt
      error = assert_raises(ArgumentError) { Encryption.decrypt(Base64.strict_encode64('short')) }

      assert_includes error.message, 'Corrupt'
    end

    def test_the_key_and_its_directory_are_private_to_the_owner
      Encryption.ensure_key

      assert_equal '600', format('%o', File.stat(Encryption::KEY_FILE).mode & 0o777)
      assert_equal '700', format('%o', File.stat(CONFIG_DIR).mode & 0o777)
    end

    def test_the_key_is_not_regenerated_once_it_exists
      Encryption.ensure_key
      key = Encryption.key
      Encryption.ensure_key

      assert_equal key, Encryption.key
    end
  end
end
