# -*- encoding: utf-8 -*-
require File.expand_path('../lib/omniauth-ldap/version', __FILE__)

Gem::Specification.new do |spec|
  spec.authors       = ["Ping Yu", "Tom Milewski"]
  spec.email         = ["ping@intridea.com", "tmilewski@gmail.com"]
  spec.description   = %q{A LDAP strategy for OmniAuth.}
  spec.summary       = %q{A LDAP strategy for OmniAuth.}
  spec.homepage      = "https://github.com/intridea/omniauth-ldap"
  spec.license       = "MIT"

  spec.add_runtime_dependency     'omniauth', '~> 2.0.0'
  spec.add_runtime_dependency     'net-ldap', '~> 0.16'
  spec.add_runtime_dependency     'pyu-ruby-sasl', '~> 0.0.3.3'
  spec.add_runtime_dependency     'rubyntlm', '~> 0.6.2'
  spec.add_development_dependency 'rspec', '~> 3.0'
  spec.add_development_dependency 'simplecov', '~> 0.11'
  spec.add_development_dependency 'rack-test', '~> 0.6', '>= 0.6.3'

  spec.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  spec.files         = `git ls-files`.split("\n")
  spec.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  spec.name          = "omniauth-ldap"
  spec.require_paths = ["lib"]
  spec.version       = OmniAuth::LDAP::VERSION

  spec.add_development_dependency("kettle-dev", "~> 1.1")
end
