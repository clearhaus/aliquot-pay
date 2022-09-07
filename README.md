# Aliquot-Pay

[![Gem Version](https://badge.fury.io/rb/aliquot-pay.svg)](https://badge.fury.io/rb/aliquot-pay)

Generate Google Pay tokens to use for testing.
Used for testing [Aliquot](https://github.com/clearhaus/aliquot).

## Generate a token and associated values.
```ruby
require 'aliquot-pay'

ap = AliquotPay.new(:ECv2)

token = ap.token

# Extract root signing keys in same form as Google supplies them.
signing_keys = ap.extract_root_signing_keys

# Extract shared secret as Base64
shared_secret = ap.shared_secret

# Extract (default) recipient id
recipient_id = ap.recipient_id
```

## Unit tests ##

To be sure that unit tests run properly, you can run them in a docker container.

```bash
docker run -ti --rm -v $(pwd):/opt/aliquot-pay ruby:2.7.4 bash
cd /opt/aliquot-pay
bundle install
bundle exec rspec
exit
```
