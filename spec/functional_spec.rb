require 'json'
require 'openssl'

require 'aliquot-pay'
require 'aliquot-pay/util'

describe AliquotPay do
  it 'works' do
    key = OpenSSL::PKey::EC.new('prime256v1').generate_key
    recipient = OpenSSL::PKey::EC.new('prime256v1').generate_key

    payment = AliquotPay.payment
    cipher = OpenSSL::Cipher::AES128.new(:CTR)
    message = AliquotPay.encrypt(JSON.unparse(payment), recipient, cipher)

    signature_string = AliquotPay.signature_string(JSON.unparse(message))

    token = {
      'protocolVersion' => 'ECv1',
      'signature' =>       AliquotPay.sign(key, signature_string),
      'signedMessage' =>   JSON.unparse(message),
    }
  end

  it 'generates ECv2 token' do
    payment = AliquotPay.payment
    recipient = OpenSSL::PKey::EC.new('prime256v1').generate_key
    root_key = OpenSSL::PKey::EC.new('prime256v1').generate_key
    intermediate_key = OpenSSL::PKey::EC.new('prime256v1').generate_key

    AliquotPay.generate_token_ecv2(payment, root_key, intermediate_key, recipient, nil)
  end
end
