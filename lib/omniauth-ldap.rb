# Integrate the VersionGem helper into the OmniAuth::LDAP::Version module
# to expose common version-related helper methods. This file is the public
# entry point required by consumers of the gem.
#
# @example
#   require 'omniauth-ldap'
#   OmniAuth::LDAP::VERSION # => "2.3.2"

require "version_gem"

require "omniauth-ldap/version"
require "omniauth-ldap/adaptor"
require "omniauth/strategies/ldap"

OmniAuth::LDAP::Version.class_eval do
  extend VersionGem::Basic
end
