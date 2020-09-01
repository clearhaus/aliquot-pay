require 'aliquot'
require 'aliquot-pay'
require 'json'
require 'base64'

shared_examples 'generation tests' do
  context 'payment-payment_method_details' do
    let(:details) { instance.build_payment_method_details }
    let(:result)  { Aliquot::Validator::PaymentMethodDetailsSchema.call(details) }

    it 'validates when PAN_ONLY' do
      expect(result.success?).to be(true), result.errors.to_s
    end

    it 'validates when CRYPTOGRAM_3DS' do
      instance.auth_method = 'CRYPTOGRAM_3DS'
      expect(result.success?).to be(true), result.errors.to_s
    end
  end

  context 'encrypted_message' do
    let(:message)  { instance.build_cleartext_message }
    let(:result)   { Aliquot::Validator::EncryptedMessageSchema.call(message) }

    it 'validates' do
      expect(result.success?).to be(true), result.errors.to_s
    end
  end

  context 'signed_message' do
    let(:message)  { instance.build_signed_message }
    let(:result)   { Aliquot::Validator::SignedMessageSchema.call(message) }

    it 'validates' do
      expect(result.success?).to be(true), result.errors.to_s
    end
  end

  context 'token' do
    let(:token)  { instance.token }
    let(:result)   { Aliquot::Validator::TokenSchema.call(token) }

    it 'validates' do
      expect(result.success?).to be(true), result.errors.to_s
    end

    it 'decrypts' do
      a = Aliquot::Payment.new(token.to_json,
                               instance.shared_secret,
                               instance.recipient_id,
                               signing_keys: instance.extract_root_signing_keys)

      expect { a.process }.to_not raise_error
    end
  end
end

describe AliquotPay do
  context :ECv1 do
    let(:instance)     { AliquotPay.new(:ECv1) }
    include_examples 'generation tests'

    it 'has the correct protocolVersion' do
      expect(instance.token['protocolVersion']).to eq('ECv1')
    end

    it 'excludes intermediateSigningKey' do
      expect(instance.token['intermediateSigningKey']).to be nil
    end
  end

  context :ECv2 do
    let(:instance)     { AliquotPay.new(:ECv2) }
    include_examples 'generation tests'

    context 'signed_key' do
      let(:message)  { instance.build_signed_key }
      let(:result)   { Aliquot::Validator::SignedKeySchema.call(message) }

      it 'validates' do
        expect(result.success?).to be(true), result.errors.to_s
      end
    end

    it 'has the correct protocolVersion' do
      expect(instance.token['protocolVersion']).to eq('ECv2')
    end
  end
end
