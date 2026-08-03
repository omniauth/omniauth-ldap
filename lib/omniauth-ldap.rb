# Compatibility shim
require "omniauth/ldap"
require "version_gem"
require_relative "omniauth/ldap/version"

OmniAuth::LDAP::Version.class_eval do
  extend VersionGem::Basic
end
