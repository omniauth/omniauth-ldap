# frozen_string_literal: true

# Skip coverage checks for single spec runs outside CI environments
begin
  ci_indicators = %w[CI GITHUB_ACTIONS GITLAB_CI TRAVIS CIRCLECI BUILD_ID CONTINUOUS_INTEGRATION]
  running_in_ci = ci_indicators.any? { |k| ENV[k] }
  requested_specs = ARGV.select { |a| a =~ %r{(^|/)spec/.+_spec\.rb(:\d+)?$} }
  if requested_specs.size == 1 && !running_in_ci
    ENV["K_SOUP_COV_DO"] = "false" unless ENV["K_SOUP_COV_DO"]
    ENV["K_SOUP_COV_MIN_HARD"] = "false" unless ENV["K_SOUP_COV_MIN_HARD"]
    ENV["K_SOUP_COV_MIN_LINE"] = "0" unless ENV["K_SOUP_COV_MIN_LINE"]
    ENV["K_SOUP_COV_MIN_BRANCH"] = "0" unless ENV["K_SOUP_COV_MIN_BRANCH"]
  end
rescue
  # ignore any detection errors
end

require "logger"
require "rack/test"

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

# RSpec Support
spec_root_matcher = %r{#{__dir__}/(.+)\.rb\Z}
Dir.glob(Pathname.new(__dir__).join("support/**/", "*.rb")).each do |f|
  m = f.match(spec_root_matcher)
  require m[1] if m
end

TEST_LOGGER = Logger.new(StringIO.new)
OmniAuth.config.logger = TEST_LOGGER
# New config for OmniAuth 2.0+
OmniAuth.config.request_validation_phase = proc {} if OmniAuth.config.respond_to?(:request_validation_phase=)

RSpec.configure do |config|
  config.include Rack::Test::Methods
  config.extend OmniAuth::Test::StrategyMacros, type: :strategy
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
