# frozen_string_literal: true

# External RSpec & related config
require "kettle/test/rspec"

# External library dependencies
require "omniauth"
require "omniauth/version"

# RSpec Configs
require "config/debug"
require "config/omniauth"
require "config/rspec/rack_test"
require "config/vcr"

require "rack/test"

# RSpec Support
spec_root_matcher = %r{#{__dir__}/(.+)\.rb\Z}
Dir.glob(Pathname.new(__dir__).join("support/**/", "*.rb")).each { |f| require f.match(spec_root_matcher)[1] }

TEST_LOGGER = Logger.new(StringIO.new)
OmniAuth.config.logger = TEST_LOGGER
OmniAuth.config.request_validation_phase = proc {}

RSpec.configure do |config|
  config.include Rack::Test::Methods
  config.extend OmniAuth::Test::StrategyMacros, :type => :strategy
end

# The last thing before loading this gem is to set up code coverage
begin
  # This does not require "simplecov", but
  require "kettle-soup-cover"
  #   this next line has a side effect of running `.simplecov`
  require "simplecov" if defined?(Kettle::Soup::Cover) && Kettle::Soup::Cover::DO_COV
rescue LoadError => error
  # check the error message and conditionally re-raise
  raise error unless error.message.include?("kettle")
end

# This gem
require "omniauth-ldap"
