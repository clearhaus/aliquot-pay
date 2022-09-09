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

To be sure that unit tests run properly, you can run them in a Docker container.

```bash
docker run -ti --rm -v $(pwd):/opt/aliquot-pay ruby:2.7.4 bash
cd /opt/aliquot-pay
bundle install
bundle exec rspec
exit
```

## Publishing new Gem

Beware of cyclic dependency with `aliquot`. Update the new versions
for these gems in parallel.

1. Update [./aliquot-pay.gemspec](./aliquot-pay.gemspec)
    ```gemspec
    Gem::Specification.new do |s|
      s.name     = 'aliquot-pay'
      s.version  = '${NEW_ALIQUOT-PAY_VERSION}'
      ...
      s.add_runtime_dependency 'aliquot', '~> ${NEW_ALIQUOT_VERSION}'
      ...
    end
    ```

2. Run the following
    ```bash
    gem build
    gem push aliquot-pay-${NEW_ALIQUOT-PAY_VERSION}.gem
    ```

3. Then do the same for `aliquot` if not already done.

