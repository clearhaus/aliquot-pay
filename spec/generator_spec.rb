require 'aliquot'
require 'aliquot-pay'
require 'json'
require 'base64'

shared_examples 'generation tests' do
  context 'encrypted_message' do
    let(:message) { instance.build_cleartext_message }
    let(:result) { Aliquot::Validator::EncryptedMessageContract.schema.call(message) }

    it 'validates' do
      expect(result.success?).to be(true), result.errors.to_s
    end
  end

  context 'signed_message' do
    let(:message) { instance.build_signed_message }
    let(:result) { Aliquot::Validator::SignedMessageContract.schema.call(message) }

    it 'validates' do
      expect(result.success?).to be(true), result.errors.to_s
    end
  end

  context 'token' do
    let(:token) { instance.token }
    let(:result) { Aliquot::Validator::TokenContract.schema.call(token) }

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

shared_examples 'ECv1' do
  it 'has the correct protocolVersion' do
    expect(instance.token['protocolVersion']).to eq('ECv1')
  end

  it 'excludes intermediateSigningKey' do
    expect(instance.token['intermediateSigningKey']).to be nil
  end

end

shared_examples 'ECv2' do
  context 'signed_key' do
    let(:message) { instance.build_signed_key }
    let(:result) { Aliquot::Validator::SignedKeyContract.schema.call(message) }

    it 'validates' do
      expect(result.success?).to be(true), result.errors.to_s
    end

    it 'has the correct protocolVersion' do
      expect(instance.token['protocolVersion']).to eq('ECv2')
    end
  end
end

describe AliquotPay do
  context :ECv1 do
    context 'non-tokenized' do
      let(:instance) { AliquotPay.new(protocol_version: :ECv1, type: :browser) }
      let(:details) { instance.build_payment_method_details }
      include_examples 'generation tests'
      it 'validates when type is browser' do
        result = Aliquot::Validator::ECv1_PaymentMethodDetailsContract.schema.call(details)
        expect(result.success?).to be(true), result.errors.to_s
      end
    end

    context 'tokenized' do
      let(:instance) { AliquotPay.new(protocol_version: :ECv1, type: :app) }
      let(:details) { instance.build_payment_method_details }
      include_examples 'generation tests'
      it 'validates when type is app' do
        details.merge!('threedsCryptogram' => details.delete('3dsCryptogram'))
        result = Aliquot::Validator::ECv1_TokenizedPaymentMethodDetailsContract.schema.call(details)
        expect(result.success?).to be(true), result.errors.to_s
      end
    end
  end

  context :ECv2 do
    context 'non-tokenized' do
      let(:instance) { AliquotPay.new(protocol_version: :ECv2, type: :browser) }
      let(:details) { instance.build_payment_method_details }
      let(:result)  { Aliquot::Validator::ECv2_PaymentMethodDetailsContract.schema.call(details) }
      include_examples 'generation tests'
      include_examples 'ECv2'
      it 'validates when browser' do
        expect(result.success?).to be(true), result.errors.to_s
      end
    end

    context 'tokenized' do
      let(:instance) { AliquotPay.new(protocol_version: :ECv2, type: :app) }
      let(:details) { instance.build_payment_method_details }
      let(:result)  { Aliquot::Validator::ECv2_TokenizedPaymentMethodDetailsContract.schema.call(details) }
      include_examples 'generation tests'
      include_examples 'ECv2'
      it 'validates when CRYPTOGRAM_3DS' do
        expect(result.success?).to be(true), result.errors.to_s
      end
    end
  end
end
