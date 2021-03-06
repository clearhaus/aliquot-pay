#lib = File.expand_path('../lib', __FILE__)
#$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |s|
  s.name     = 'aliquot-pay'
  s.version  = '2.0.0'
  s.author   = 'Clearhaus'
  s.email    = 'hello@clearhaus.com'
  s.summary  = 'Generates Google Pay test dummy tokens'
  s.license  = 'MIT'
  s.homepage = 'https://github.com/clearhaus/aliquot-pay'

  s.files = Dir.glob('lib/**/*.rb')

  # Ruby 2.3 OpenSSL does not support KDF (hkdf).
  s.add_runtime_dependency 'hkdf', '~> 0.3'
  s.add_runtime_dependency 'aliquot', '~> 2.0.0'

  s.add_development_dependency 'rspec', '~> 3'
end
