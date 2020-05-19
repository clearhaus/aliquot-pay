require 'openssl'
require 'hkdf'

class AliquotPay
  class Util
    class << self
      def generate_ephemeral_key
        OpenSSL::PKey::EC.new(AliquotPay::EC_CURVE).generate_key
      end

      def generate_shared_key(private_key, public_key)
        private_key.dh_compute_key(public_key)
      end

      alias :generate_shared_secret :generate_shared_key

      def derive_keys(ephemeral_public_key, shared_key, info, protocol_version = :ECv2)
        case protocol_version
        when :ECv1
          key_length = 16
        when :ECv2
          key_length = 32
        else
          raise StandardError, "invalid protocol_version #{protocol_version}"
        end

        input_keying_material = ephemeral_public_key + shared_key
        if OpenSSL.const_defined?(:KDF) && OpenSSL::KDF.respond_to?(:hkdf)
          h = OpenSSL::Digest::SHA256.new
          hbytes = OpenSSL::KDF.hkdf(input_keying_material, hash: h, salt: '', length: key_length * 2, info: info)
        else
          hbytes = HKDF.new(input_keying_material, algorithm: 'SHA256', info: info).next_bytes(key_length * 2)
        end

        {
          aes_key: hbytes[0, key_length],
          mac_key: hbytes[key_length, key_length],
        }
      end

      def calculate_tag(mac_key, encrypted_message)
        digest = OpenSSL::Digest::SHA256.new
        OpenSSL::HMAC.digest(digest, mac_key, encrypted_message)
      end
    end
  end
end
