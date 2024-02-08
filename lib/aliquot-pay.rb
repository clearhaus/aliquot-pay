require 'base64'
require 'openssl'
require 'json'

require 'aliquot-pay/util'

class AliquotPay
  class Error < StandardError; end

  EC_CURVE = 'prime256v1'.freeze

  DEFAULTS = {
    info: 'Google',
    recipient_id: 'merchant:0123456789',
  }.freeze

  attr_accessor :signature, :intermediate_signing_key, :signed_message
  attr_accessor :signed_key, :signatures
  attr_accessor :key_expiration, :key_value
  attr_accessor :encrypted_message, :cleartext_message, :ephemeral_public_key, :tag
  attr_accessor :message_expiration, :message_id, :payment_method, :payment_method_details, :gateway_merchant_id
  attr_accessor :pan, :expiration_month, :expiration_year, :auth_method
  attr_accessor :cryptogram, :eci_indicator

  attr_accessor :recipient, :info, :root_key, :intermediate_key
  attr_writer   :recipient_id, :shared_secret, :token, :signed_key_string

  def initialize(protocol_version: :ECv2, root_key: nil, type: :browser)
    @protocol_version = protocol_version
    @root_key = root_key
    @type = type
  end

  def token
    build_token
  end

  def extract_root_signing_keys
    key = Base64.strict_encode64(ensure_root_key.to_der)
    {
      'keys' => [
        'protocolVersion' => @protocol_version,
        'keyValue'        => key
      ]
    }.to_json
  end

  def sign(key, message)
    d = OpenSSL::Digest::SHA256.new
    def key.private?
      private_key?
    end
    Base64.strict_encode64(key.sign(d, message))
  end

  def encrypt(cleartext_message)
    @recipient ||= OpenSSL::PKey::EC.generate('prime256v1')
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
      raise StandardError, "Invalid protocol_version #{@protocol_version}"
    end

    keys = AliquotPay::Util.derive_keys(eph.public_key.to_bn.to_s(2), ss, @info, @protocol_version)

    cipher.encrypt
    cipher.key = keys[:aes_key]

    encrypted_message = cipher.update(cleartext_message) + cipher.final

    tag = AliquotPay::Util.calculate_tag(keys[:mac_key], encrypted_message)

    {
      'encryptedMessage'   => Base64.strict_encode64(encrypted_message),
      'ephemeralPublicKey' => Base64.strict_encode64(eph.public_key.to_bn.to_s(2)),
      'tag'                => Base64.strict_encode64(tag)
    }
  end

  def build_payment_method_details
    return @payment_method_details if @payment_method_details

    return build_payment_method_details_non_tokenized if @type == :browser

    build_payment_method_details_tokenized
  end

  def build_payment_method_details_non_tokenized
    value = {
      'pan'             => @pan              || '4111111111111111',
      'expirationYear'  => @expiration_year  || Time.now.year + 1,
      'expirationMonth' => @expiration_month || 12
    }

    if @protocol_version == :ECv2 && @type == :browser
      value.merge!(
        'authMethod' => @auth_method || 'PAN_ONLY'
      )
    end
    value
  end

  def build_payment_method_details_tokenized
    value = {
      'expirationYear'  => @expiration_year  || Time.now.year + 1,
      'expirationMonth' => @expiration_month || 12,
      'eciIndicator'  => @eci_indicator || '05'
    }
    if @protocol_version == :ECv1
      value.merge!(
        'dpan'          => @pan           || '4111111111111111',
        'authMethod'    => @auth_method   || '3DS',
        '3dsCryptogram' => @cryptogram    || Base64.strict_encode64(OpenSSL::Random.random_bytes(20))
      )
    else
      value.merge!(
        'pan'          => @pan           || '4111111111111111',
        'authMethod'   => @auth_method   || 'CRYPTOGRAM_3DS',
        'cryptogram'   => @cryptogram    || Base64.strict_encode64(OpenSSL::Random.random_bytes(20))
      )
    end
  end

  def build_cleartext_message
    return @cleartext_message if @cleartext_message

    default_message_id = Base64.strict_encode64(OpenSSL::Random.random_bytes(24))
    default_message_expiration = ((Time.now.to_f + 60 * 5) * 1000).round.to_s

    @cleartext_message = {
      'messageExpiration'    => @message_expiration || default_message_expiration,
      'messageId'            => @message_id         || default_message_id,
      'paymentMethod'        => @payment_method     || 'CARD',
      'paymentMethodDetails' => build_payment_method_details
    }

    if @protocol_version == :ECv2
      @cleartext_message.merge!(
        'gatewayMerchantId' => @gateway_merchant_id || 'SOME GATEWAY MERCHANT ID'
      )
    end

    @cleartext_message
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
    build_signed_message.to_json
  end

  def build_signed_key
    return @signed_key if @signed_key

    ensure_intermediate_key

    if !@intermediate_key.private_key? && !@intermediate_key.public_key?
      fail 'Intermediate key must be public and private key'
    end

    default_key_value      = Base64.strict_encode64(@intermediate_key.to_der)
    default_key_expiration = "#{Time.now.to_i + 3600}000"

    @signed_key = {
      'keyExpiration' => @key_expiration || default_key_expiration,
      'keyValue'      => @key_value      || default_key_value
    }
  end

  def signed_key_string
    @signed_key_string ||= build_signed_key.to_json
  end

  def ensure_root_key
    @root_key ||= OpenSSL::PKey::EC.generate(EC_CURVE)
  end

  def ensure_intermediate_key
    @intermediate_key ||= OpenSSL::PKey::EC.generate(EC_CURVE)
  end

  def build_signature
    return @signature if @signature
    key = case @protocol_version
          when :ECv1
            ensure_root_key
          when :ECv2
            ensure_intermediate_key
          end

    signature_elements = [
      'Google',
      recipient_id,
      @protocol_version.to_s,
      signed_message_string
    ]

    signature_string = signature_elements.map { |e| [e.length].pack('V') + e }.join
    @signature = sign(key, signature_string)
  end

  def build_signatures
    return @signatures if @signatures

    signature_string = ['Google', 'ECv2', signed_key_string].map do |str|
      [str.to_s.length].pack('V') + str.to_s
    end.join

    @signatures = [sign(ensure_root_key, signature_string)]
  end

  def build_token
    return @token if @token

    if @type == :app
      @auth_method = 'CRYPTOGRAM_3DS'
      if @protocol_version == :ECv1
        @auth_method = '3DS'
        @payment_method = 'TOKENIZED_CARD'
      end
    end

    res = {
      'protocolVersion' => @protocol_version.to_s,
      'signedMessage'   => @signed_message || signed_message_string,
      'signature'       => build_signature
    }

    if @protocol_version == :ECv2
      intermediate = {
        'intermediateSigningKey' => @intermediate_signing_key || {
          'signedKey'  => signed_key_string,
          'signatures' => build_signatures
        }
      }

      res.merge!(intermediate)
    end

    @token = res
  end

  def recipient_id
    @recipient_id ||= DEFAULTS[:recipient_id]
  end

  def shared_secret
    return Base64.strict_encode64(@shared_secret) if @shared_secret
    @shared_secret ||= Random.new.bytes(32)
    shared_secret
  end
end
