require 'json'
require 'openssl'

require 'aliquot-pay'
require 'aliquot-pay/util'

describe AliquotPay do
  it 'works' do
    key = OpenSSL::PKey::EC.new('prime256v1').generate_key
    recipient = OpenSSL::PKey::EC.new('prime256v1').generate_key

    payment = AliquotPay.payment
    message = AliquotPay.encrypt(payment.to_json, recipient, :ECv1)

    signature_string = AliquotPay.signature_string(message.to_json)

    token = {
      'protocolVersion' => 'ECv1',
      'signature' =>       AliquotPay.sign(key, signature_string),
      'signedMessage' =>   message.to_json,
    }
  end

  it 'generates ECv2 token' do
    payment = AliquotPay.payment
    recipient = OpenSSL::PKey::EC.new('prime256v1').generate_key
    root_key = OpenSSL::PKey::EC.new('prime256v1').generate_key
    intermediate_key = OpenSSL::PKey::EC.new('prime256v1').generate_key

    AliquotPay.generate_token_ecv2(payment, root_key, intermediate_key, recipient)
  end
end
