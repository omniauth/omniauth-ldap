require "anonymous_loader"

module OmniAuth
  module LDAP
    # See: Zero Top-Level Namespace Additions
    #      https://github.com/ruby-oauth/auth-sanitizer/blob/main/README.md#zero-top-level-namespace-additions
    AUTH_SANITIZER = begin
      auth_sanitizer_requirement = Gem::Requirement.new("~> 0.2", ">= 0.2.2")
      auth_sanitizer_loader_namespace = AnonymousLoader.load_path(
        gem_name: "auth-sanitizer",
        require_path: "auth_sanitizer/loader.rb",
        version_requirement: auth_sanitizer_requirement,
        version_file: "auth/sanitizer/version.rb"
      )

      auth_sanitizer_loader_namespace
        .const_get(:AuthSanitizer)
        .const_get(:Loader)
        .load_isolated
    end
  end
end
