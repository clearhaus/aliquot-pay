require 'openssl'
require 'hkdf'

class AliquotPay
  class Util
    def self.generate_ephemeral_key
      OpenSSL::PKey::EC.generate(AliquotPay::EC_CURVE)
    end

    def self.generate_shared_secret(private_key, public_key)
      private_key.dh_compute_key(public_key)
    end

    def self.derive_keys(ephemeral_public_key, shared_secret, info, protocol_version = :ECv2)
      case protocol_version
      when :ECv1
        key_length = 16
      when :ECv2
        key_length = 32
      else
        raise StandardError, "invalid protocol_version #{protocol_version}"
      end

      input_keying_material = ephemeral_public_key + shared_secret
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

    def self.calculate_tag(mac_key, encrypted_message)
      digest = OpenSSL::Digest::SHA256.new
      OpenSSL::HMAC.digest(digest, mac_key, encrypted_message)
    end
  end
end
