module OmniAuth
  module LDAP
    # Version namespace for the omniauth-ldap gem
    #
    # This module contains the version constant used by rubygems and in code
    # consumers. It intentionally exposes VERSION both inside the Version
    # namespace and as OmniAuth::LDAP::VERSION for compatibility.
    module Version
      # Public semantic version for the gem
      # @return [String]
      VERSION = "2.3.2"
    end
    # Convenience constant for consumers that expect OmniAuth::LDAP::VERSION
    # @return [String]
    VERSION = Version::VERSION # Make VERSION available in traditional way
  end
end
