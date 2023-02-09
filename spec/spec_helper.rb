$:.unshift File.expand_path('..', __FILE__)
$:.unshift File.expand_path('../../lib', __FILE__)
require 'simplecov'
SimpleCov.start
require 'rspec'
require 'rack/test'
require 'omniauth'
require 'omniauth-ldap'

TEST_LOGGER = Logger.new(StringIO.new)
OmniAuth.config.logger = TEST_LOGGER
OmniAuth.config.request_validation_phase = proc {}

RSpec.configure do |config|
  config.include Rack::Test::Methods
  config.extend  OmniAuth::Test::StrategyMacros, :type => :strategy
end

