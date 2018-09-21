require 'openssl'
require 'hkdf'

require 'pry'

module AliquotPay
  class Util
    def self.generate_ephemeral_key
      OpenSSL::PKey::EC.new(AliquotPay::EC_CURVE).generate_key
    end

    def self.generate_shared_secret(ephemeral_key, public_key)
      ephemeral_key.dh_compute_key(public_key)
    end

    def self.derive_keys(ephemeral_public_key, shared_secret, info)
      ikm = ephemeral_public_key + shared_secret
      hbytes = HKDF.new(ikm, algorithm: 'SHA256', info: info).next_bytes(32)

      {
        aes_key: hbytes[0..15],
        mac_key: hbytes[16..32],
      }
    end

    def self.calculate_tag(mac_key, encrypted_message)
      digest = OpenSSL::Digest::SHA256.new
      OpenSSL::HMAC.digest(digest, mac_key, encrypted_message)
    end
  end
end
