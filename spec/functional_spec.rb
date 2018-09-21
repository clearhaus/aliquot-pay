require 'json'

require 'aliquot-pay'
require 'aliquot-pay/util'

describe AliquotPay do
  it 'works' do
    key = OpenSSL::PKey::EC.new('prime256v1').generate_key
    recipient = OpenSSL::PKey::EC.new('prime256v1').generate_key

    payment = AliquotPay.payment
    message = AliquotPay.encrypt(JSON.unparse(payment), recipient)

    signature_string = AliquotPay.signature_string(JSON.unparse(message))

    token = {
      'protocolVersion' => 'ECv1',
      'signature' =>       AliquotPay.sign(key, signature_string),
      'signedMessage' =>   JSON.unparse(message),
    }
  end
end
