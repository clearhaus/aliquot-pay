require 'base64'
require 'openssl'
require 'json'

require 'aliquot-pay/util'

module AliquotPay
  class Error < StandardError; end

  EC_CURVE = 'prime256v1'.freeze

  DEFAULTS = {
    info: 'Google',
    merchant_id: 'merchant:0123456789',
  }.freeze

  def self.sign(key, message)
    d = OpenSSL::Digest::SHA256.new
    def key.private?; private_key?; end
    Base64.strict_encode64(key.sign(d, message))
  end

  def self.encrypt(cleartext_message, recipient, cipher, info = 'Google')
    eph = AliquotPay::Util.generate_ephemeral_key
    ss  = AliquotPay::Util.generate_shared_secret(eph, recipient.public_key)

    keys = AliquotPay::Util.derive_keys(eph.public_key.to_bn.to_s(2), ss, info, length: cipher.key_len)

    cipher.encrypt
    cipher.key = keys[:aes_key]

    encrypted_message = cipher.update(cleartext_message) + cipher.final

    tag = AliquotPay::Util.calculate_tag(keys[:mac_key], encrypted_message)

    {
      encryptedMessage: Base64.strict_encode64(encrypted_message),
      ephemeralPublicKey: Base64.strict_encode64(eph.public_key.to_bn.to_s(2)),
      tag: Base64.strict_encode64(tag),
    }
  end

  # Return a default payment
  def self.payment(
    auth_method: :PAN_ONLY,
    expiration: ((Time.now.to_f + 60 * 5) * 1000).round.to_s
  )
    id = Base64.strict_encode64(OpenSSL::Random.random_bytes(24))
    p = {
      'messageExpiration'    => expiration,
      'messageId'            => id,
      'paymentMethod'        => 'CARD',
      'paymentMethodDetails' => {
        'expirationYear'  => 2023,
        'expirationMonth' => 12,
        'pan'             => '4111111111111111',
        'authMethod'      => 'PAN_ONLY',
      },
    }

    if auth_method == :CRYPTOGRAM_3DS
      p['paymentMethodDetails']['authMethod']   = 'CRYPTOGRAM_3DS'
      p['paymentMethodDetails']['cryptogram']   = 'SOME CRYPTOGRAM'
      p['paymentMethodDetails']['eciIndicator'] = '05'
    end

    p
  end

  # Return a string length as a 4byte little-endian integer, as a string
  def self.four_byte_length(str)
    [str.length].pack('V')
  end

  def self.generate_signature(*args)
    args.map do |s|
      four_byte_length(s) + s
    end.join('')
  end

  def self.signature_string(
    message,
    recipient_id     = DEFAULTS[:merchant_id],
    sender_id        = DEFAULTS[:info],
    protocol_version = 'ECv1'
  )

    generate_signature(sender_id, recipient_id, protocol_version, message)
  end

  # payment::        Google Pay token as a ruby Hash
  # signing_key::    OpenSSL::PKEY::EC
  # recipient::      OpenSSL::PKey::EC
  # signed_message:: Pass a customized message to sign as signed messaged.
  def self.generate_token_ecv1(payment, signing_key, recipient, signed_message = nil)
    cipher = OpenSSL::Cipher::AES128.new(:CTR)
    signed_message ||= JSON.unparse(encrypt(JSON.unparse(payment), recipient, cipher))
    signature_string = signature_string(signed_message)

    {
      'protocolVersion' => 'ECv1',
      'signature' =>       sign(signing_key, signature_string),
      'signedMessage' =>   signed_message,
    }
  end

  def self.generate_token_ecv2(payment, signing_key, intermediate_key, recipient, signed_message)
    cipher = OpenSSL::Cipher::AES256.new(:CTR)
    signed_message ||= JSON.unparse(encrypt(JSON.unparse(payment), recipient, cipher))
    signature_string = signature_string(signed_message)

    signed_key = JSON.unparse(
      'keyExpiration' => "#{Time.now.to_i + 3600}000",
      'keyValue'      => Base64.strict_encode64(intermediate_key.public_key.to_bn.to_s(2))
    )

    ik_signature_string = generate_signature('Google', 'ECv2', signed_key)
    signatures = [sign(signing_key, ik_signature_string)]

    {
      'protocolVersion' => 'ECv2',
      'signature' =>       sign(intermediate_key, signature_string),
      'signedMessage' =>   signed_message,
      'interMediateSigningKey' => {
        'signedKey'  => signed_key,
        'signatures' => signatures,
      },
    }
  end
end
