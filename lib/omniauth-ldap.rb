require "omniauth-ldap/version"
require "omniauth-ldap/adaptor"
require 'omniauth/strategies/ldap'

OmniAuth::LDAP::Version.class_eval do
  extend VersionGem::Basic
end
