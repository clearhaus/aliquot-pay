require 'base64'
require 'openssl'
require 'json'

require 'aliquot-pay/util'

class AliquotPay
  class Error < StandardError; end

  EC_CURVE = 'prime256v1'.freeze

  DEFAULTS = {
    info: 'Google',
    merchant_id: '0123456789',
  }.freeze

  attr_accessor :signature, :intermediate_signing_key, :signed_message
  attr_accessor :signed_key, :signatures
  attr_accessor :key_expiration, :key_value
  attr_accessor :encrypted_message, :cleartext_message, :ephemeral_public_key, :tag
  attr_accessor :message_expiration, :message_id, :payment_method, :payment_method_details
  attr_accessor :pan, :expiration_month, :expiration_year, :auth_method
  attr_accessor :cryptogram, :eci_indicator

  attr_accessor :recipient, :info, :root_key, :intermediate_key
  attr_writer   :merchant_id, :shared_secret, :token, :signed_key_string

  def initialize(protocol_version = :ECv2)
    @protocol_version = protocol_version
  end

  def self.sign(key, message)
    d = OpenSSL::Digest::SHA256.new
    def key.private?; private_key?; end
    Base64.strict_encode64(key.sign(d, message))
  end

  def self.encrypt(cleartext_message, recipient, protocol_version, info = 'Google')
    eph = AliquotPay::Util.generate_ephemeral_key
    ss  = AliquotPay::Util.generate_shared_secret(eph, recipient.public_key)

    case protocol_version
    when :ECv1
      cipher = OpenSSL::Cipher::AES128.new(:CTR)
    when :ECv2
      cipher = OpenSSL::Cipher::AES256.new(:CTR)
    else
      raise StandardError, "Invalid protocol_version #{protocol_version}"
    end

    keys = AliquotPay::Util.derive_keys(eph.public_key.to_bn.to_s(2), ss, info, protocol_version)

    cipher.encrypt
    cipher.key = keys[:aes_key]

    encrypted_message = cipher.update(cleartext_message) + cipher.final

    tag = AliquotPay::Util.calculate_tag(keys[:mac_key], encrypted_message)

    {
      'encryptedMessage'   => Base64.strict_encode64(encrypted_message),
      'ephemeralPublicKey' => Base64.strict_encode64(eph.public_key.to_bn.to_s(2)),
      'tag'                => Base64.strict_encode64(tag),
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
    end.join
  end

  def self.signature_string(
    message,
    merchant_id:      DEFAULTS[:merchant_id],
    sender_id:        DEFAULTS[:info],
    protocol_version: 'ECv1'
  )

    generate_signature(sender_id, "merchant:#{merchant_id}", protocol_version, message)
  end

  # payment::        Google Pay token as a ruby Hash
  # signing_key::    OpenSSL::PKEY::EC
  # recipient::      OpenSSL::PKey::EC
  # signed_message:: Pass a customized message to sign as signed messaged.
  def self.generate_token_ecv1(payment, signing_key, recipient, signed_message = nil)
    signed_message ||= encrypt(payment.to_json, recipient, :ECv1).to_json
    signature_string = signature_string(signed_message)

    {
      'protocolVersion' => 'ECv1',
      'signature' =>       sign(signing_key, signature_string),
      'signedMessage' =>   signed_message,
    }
  end

  def self.generate_token_ecv2(payment, signing_key, intermediate_key, recipient,
                               signed_message: nil, expire_time:  "#{Time.now.to_i + 3600}000")
    signed_message ||= encrypt(payment.to_json, recipient, :ECv2).to_json
    sig = signature_string(signed_message, protocol_version: 'ECv2')

    intermediate_pub = OpenSSL::PKey::EC.new(EC_CURVE)
    intermediate_pub.public_key = intermediate_key.public_key

    signed_key = {
      'keyExpiration' => expire_time,
      'keyValue'      => Base64.strict_encode64(intermediate_pub.to_der)
    }.to_json

    ik_signature_string = generate_signature('Google', 'ECv2', signed_key)
    signatures = [sign(signing_key, ik_signature_string)]

    {
      'protocolVersion' => 'ECv2',
      'signature' =>       sign(intermediate_key, sig),
      'signedMessage' =>   signed_message,
      'intermediateSigningKey' => {
        'signedKey'  => signed_key,
        'signatures' => signatures,
      },
    }
  end

  def token
    build_token
  end

  def extract_root_signing_keys
    key = Base64.strict_encode64(eckey_to_public(ensure_root_key).to_der)
    {
      'keys' => [
        'protocolVersion' => @protocol_version,
        'keyValue'        => key,
      ]
    }.to_json
  end

  def eckey_to_public(key)
    p = OpenSSL::PKey::EC.new(EC_CURVE)

    p.public_key = key.public_key

    p
  end

  #private

  def sign(key, message)
    d = OpenSSL::Digest::SHA256.new
    def key.private?; private_key?; end
    Base64.strict_encode64(key.sign(d, message))
  end

  def encrypt(cleartext_message)
    @recipient ||= OpenSSL::PKey::EC.new('prime256v1').generate_key
    @info ||= 'Google'

    eph = AliquotPay::Util.generate_ephemeral_key
    @shared_secret ||= AliquotPay::Util.generate_shared_secret(eph, @recipient.public_key)
    ss  = @shared_secret

    case @protocol_version
    when :ECv1
      cipher = OpenSSL::Cipher::AES128.new(:CTR)
    when :ECv2
      cipher = OpenSSL::Cipher::AES256.new(:CTR)
    else
      raise StandardError, "Invalid protocol_version #{protocol_version}"
    end

    keys = AliquotPay::Util.derive_keys(eph.public_key.to_bn.to_s(2), ss, @info, @protocol_version)

    cipher.encrypt
    cipher.key = keys[:aes_key]

    encrypted_message = cipher.update(cleartext_message) + cipher.final

    tag = AliquotPay::Util.calculate_tag(keys[:mac_key], encrypted_message)

    {
      'encryptedMessage'   => Base64.strict_encode64(encrypted_message),
      'ephemeralPublicKey' => Base64.strict_encode64(eph.public_key.to_bn.to_s(2)),
      'tag'                => Base64.strict_encode64(tag),
    }
  end

  def build_payment_method_details
    return @payment_method_details if @payment_method_details
    value = {
      'pan'             => @pan              || '4111111111111111',
      'expirationYear'  => @expiration_year  || 2023,
      'expirationMonth' => @expiration_month || 12,
      'authMethod'     => @auth_method      || 'PAN_ONLY',
    }

    if @auth_method == 'CRYPTOGRAM_3DS'
      value.merge!(
        'cryptogram'   => @cryptogram    || 'SOME CRYPTOGRAM',
        'eciIndicator' => @eci_indicator || '05'
      )
    end

    value
  end

  def build_cleartext_message
    return @cleartext_message if @cleartext_message
    default_message_id = Base64.strict_encode64(OpenSSL::Random.random_bytes(24))
    default_message_expiration = ((Time.now.to_f + 60 * 5) * 1000).round.to_s

    @cleartext_message = {
      'messageExpiration'    => @message_expiration || default_message_expiration,
      'messageId'            => @message_id || default_message_id,
      'paymentMethod'        => @payment_method || 'CARD',
      'paymentMethodDetails' => build_payment_method_details
    }
  end

  def build_signed_message
    return @signed_message if @signed_message

    signed_message = encrypt(build_cleartext_message.to_json)
    signed_message['encryptedMessage']   = @encrypted_message if @encrypted_message
    signed_message['ephemeralPublicKey'] = @ephemeral_public_key if @ephemeral_public_key
    signed_message['tag']                = @tag if @tag

    @signed_message = signed_message
  end

  def signed_message_string
    @signed_message_string ||= build_signed_message.to_json
  end

  def build_signed_key
    return @signed_key if @signed_key
    ensure_intermediate_key

    if @intermediate_key.private_key? || @intermediate_key.public_key?
      public_key = eckey_to_public(@intermediate_key)
    else
      fail 'Intermediate key must be public and private key'
    end

    default_key_value      = Base64.strict_encode64(public_key.to_der)
    default_key_expiration = "#{Time.now.to_i + 3600}000"

    @signed_key = {
      'keyExpiration' => @key_expiration || default_key_expiration,
      'keyValue'      => @key_value || default_key_value,
    }
  end

  def signed_key_string
    @signed_key_string ||= build_signed_key.to_json
  end

  def ensure_root_key
    @root_key ||= OpenSSL::PKey::EC.new(EC_CURVE).generate_key
  end

  def ensure_intermediate_key
    @intermediate_key ||= OpenSSL::PKey::EC.new(EC_CURVE).generate_key
  end

  def build_signature
    return @signature if @signature
    key = case @protocol_version
          when :ECv1
            ensure_root_key
          when :ECv2
            ensure_intermediate_key
          end

    signature_string =
      signed_string_message = ['Google',
                               "merchant:#{merchant_id}",
                               @protocol_version.to_s,
                               signed_message_string].map do |str|
        [str.length].pack('V') + str
      end.join
    @signature = sign(key, signature_string)
  end

  def build_signatures
    return @signatures if @signatures

    signature_string =
      signed_key_signature = ['Google', 'ECv2', signed_key_string].map do |str|
        [str.to_s.length].pack('V') + str.to_s
      end.join

    @signatures = [sign(ensure_root_key, signature_string)]
  end

  def build_token
    return @token if @token
    res = {
      'protocolVersion' => @protocol_version.to_s,
      'signedMessage'   => @signed_message || signed_message_string,
      'signature'       => build_signature,
    }

    if @protocol_version == :ECv2
      intermediate = {
        'intermediateSigningKey' => @intermediate_signing_key || {
          'signedKey'  => signed_key_string,
          'signatures' => build_signatures,
        }
      }

      res.merge!(intermediate)
    end

    @token = res
  end

  def merchant_id
    @merchant_id ||= DEFAULTS[:merchant_id]
  end

  def shared_secret
    return Base64.strict_encode64(@shared_secret) if @shared_secret
    @shared_secret ||= Random.new.bytes(32)
    shared_secret
  end
end
