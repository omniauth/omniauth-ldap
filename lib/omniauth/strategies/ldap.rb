# frozen_string_literal: true

require "omniauth"
require "omniauth/version"

# OmniAuth strategies namespace.
#
# This file implements an LDAP authentication strategy for OmniAuth.
# It provides both an interactive request phase (login form) and a
# callback phase which binds to an LDAP directory to authenticate the
# user or performs a lookup for header-based SSO.
#
# The strategy exposes a number of options (see `option` calls below)
# that control LDAP connection, mapping of LDAP attributes to the
# OmniAuth `info` hash, header-based SSO behavior, and SSL/timeouts.
#
# @example Minimal Rack mounting
#   use OmniAuth::Builder do
#     provider :ldap, {
#       host: 'ldap.example.com',
#       base: 'dc=example,dc=com'
#     }
#   end
#
module OmniAuth
  module Strategies
    # LDAP OmniAuth strategy
    #
    # This class implements the OmniAuth::Strategy interface and performs
    # LDAP authentication using an `Adaptor` object. It supports three
    # primary flows:
    #
    # - Interactive login form (request_phase) where users POST username/password
    # - Callback binding where the strategy attempts to bind as the user
    # - Header-based SSO (trusted upstream) where a header identifies the user
    #
    # The mapping from LDAP attributes to resulting `info` fields is
    # configurable via the `:mapping` option. See `map_user` for the
    # mapping algorithm.
    #
    # @see OmniAuth::Strategy
    class LDAP
      # Whether the loaded OmniAuth version is >= 2.0.0; used to set default request methods.
      # @return [Boolean]
      OMNIAUTH_GTE_V2 = Gem::Version.new(OmniAuth::VERSION) >= Gem::Version.new("2.0.0")

      include OmniAuth::Strategy

      # Raised when credentials are invalid or the user cannot be authenticated.
      # @example
      #   raise InvalidCredentialsError, 'Invalid credentials'
      InvalidCredentialsError = Class.new(StandardError)

      # Default mapping for converting LDAP attributes to OmniAuth `info` keys.
      # Keys are the resulting `info` hash keys (strings). Values may be:
      # - String: single LDAP attribute name
      # - Array: list of attribute names in priority order
      # - Hash: pattern mapping where pattern keys contain %<n> placeholders
      #   that are substituted from a list of possible attribute names
      #
      # @return [Hash<String, String|Array|Hash>]
      option :mapping, {
        "name" => "cn",
        "first_name" => "givenName",
        "last_name" => "sn",
        "email" => ["mail", "email", "userPrincipalName"],
        "phone" => ["telephoneNumber", "homePhone", "facsimileTelephoneNumber"],
        "mobile" => ["mobile", "mobileTelephoneNumber"],
        "nickname" => ["uid", "userid", "sAMAccountName"],
        "title" => "title",
        "location" => {"%0, %1, %2, %3 %4" => [["address", "postalAddress", "homePostalAddress", "street", "streetAddress"], ["l"], ["st"], ["co"], ["postOfficeBox"]]},
        "uid" => "dn",
        "url" => ["wwwhomepage"],
        "image" => "jpegPhoto",
        "description" => "description",
      }

      # Default title shown on the login form.
      # @return [String]
      option :title, "LDAP Authentication"

      # For OmniAuth >= 2.0 the default allowed request method is POST only.
      # Ensure the strategy follows that default so GET /auth/:provider returns 404 as expected in tests.
      if OMNIAUTH_GTE_V2
        option(:request_methods, [:post])
      else
        option(:request_methods, [:get, :post])
      end

      # Default LDAP connection options / behavior
      option :port, 389
      option :method, :plain
      option :disable_verify_certificates, false
      option :ca_file, nil
      option :ssl_version, nil # use OpenSSL default if nil
      option :uid, "sAMAccountName"
      option :name_proc, lambda { |n| n }

      # Trusted header SSO support (disabled by default)
      # :header_auth - when true and the header is present, the strategy trusts the upstream gateway
      #                 and searches the directory for the user without requiring a user password.
      # :header_name - which header/env key to read (default: "REMOTE_USER"). We will also check the
      #                 standard Rack "HTTP_" variant automatically.
      option :header_auth, false
      option :header_name, "REMOTE_USER"

      # Optional timeouts (forwarded to Net::LDAP when supported)
      option :connect_timeout, nil
      option :read_timeout, nil

      # Request phase: Render the login form or redirect to callback for header-auth or direct POSTed credentials
      #
      # This will behave differently depending on OmniAuth version and request method:
      # - For OmniAuth >= 2.0 a GET to /auth/:provider should return 404 (so we return a 404 for GET requests).
      # - If header-based SSO is enabled and a trusted header is present we immediately redirect to the callback.
      # - If credentials are POSTed directly to /auth/:provider we redirect to the callback so the test helpers
      #   that populate `env['omniauth.auth']` can operate on the callback request.
      #
      # @return [Array] A Rack response triple from the login form or redirect.
      def request_phase
        # OmniAuth >= 2.0 expects the request phase to be POST-only for /auth/:provider.
        # Some test environments (and OmniAuth itself) enforce this by returning 404 on GET.
        if OMNIAUTH_GTE_V2 && request.get?
          return Rack::Response.new("", 404, {"Content-Type" => "text/plain"}).finish
        end

        # Fast-path: if a trusted identity header is present, skip the login form
        # and jump to the callback where we will complete using directory lookup.
        if header_username
          return Rack::Response.new([], 302, "Location" => callback_url).finish
        end

        # If credentials were POSTed directly to /auth/:provider, redirect to the callback path.
        # This mirrors the behavior of many OmniAuth providers and allows test helpers (like
        # OmniAuth::Test::PhonySession) to populate `env['omniauth.auth']` on the callback request.
        if request.post? && request_data["username"].to_s != "" && request_data["password"].to_s != ""
          return Rack::Response.new([], 302, "Location" => callback_url).finish
        end

        OmniAuth::LDAP::Adaptor.validate(@options)
        f = OmniAuth::Form.new(title: options[:title] || "LDAP Authentication", url: callback_url)
        f.text_field("Login", "username")
        f.password_field("Password", "password")
        f.button("Sign In")
        f.to_response
      end

      # Callback phase: Authenticate user or perform header-based lookup
      #
      # This method executes on the callback URL and implements the main
      # authentication logic. There are two primary paths:
      #
      # - Header-based lookup: when `options[:header_auth]` is enabled and a header value is present,
      #   we perform a read-only directory lookup for the user and, if found, map attributes and finish.
      # - Password bind: when username/password are provided we attempt a bind as the user using the adaptor.
      #
      # Errors raised by the LDAP adaptor are captured and turned into OmniAuth failures.
      #
      # @raise [InvalidCredentialsError] when credentials are invalid
      # @return [Object] result of calling `super` from the OmniAuth::Strategy chain
      def callback_phase
        @adaptor = OmniAuth::LDAP::Adaptor.new(@options)

        return fail!(:invalid_request_method) unless valid_request_method?

        # Header-based SSO (REMOTE_USER-style) path
        if (hu = header_username)
          begin
            entry = directory_lookup(@adaptor, hu)
            unless entry
              return fail!(:invalid_credentials, InvalidCredentialsError.new("User not found for header #{hu}"))
            end
            @ldap_user_info = entry
            @user_info = self.class.map_user(@options[:mapping], @ldap_user_info)
            return super
          rescue => e
            return fail!(:ldap_error, e)
          end
        end

        return fail!(:missing_credentials) if missing_credentials?
        begin
          @ldap_user_info = @adaptor.bind_as(filter: filter(@adaptor), size: 1, password: request_data["password"])

          unless @ldap_user_info
            # Attach password policy info to env if available (best-effort)
            attach_password_policy_env(@adaptor)
            return fail!(:invalid_credentials, InvalidCredentialsError.new("Invalid credentials for #{request_data["username"]}"))
          end

          # Optionally attach policy info even on success (e.g., timeBeforeExpiration)
          attach_password_policy_env(@adaptor)

          @user_info = self.class.map_user(@options[:mapping], @ldap_user_info)
          super
        rescue => e
          fail!(:ldap_error, e)
        end
      end

      # Build an LDAP filter for searching/binding the user.
      #
      # If the adaptor has a custom `filter` option set it will be used (with
      # interpolation of `%{username}`). Otherwise a simple equality filter for
      # the configured uid attribute is used.
      #
      # @param adaptor [OmniAuth::LDAP::Adaptor] the adaptor used to build connection/filters
      # @param username_override [String, nil] optional username to build the filter for (defaults to request username)
      # @return [Net::LDAP::Filter] the constructed filter object
      def filter(adaptor, username_override = nil)
        flt = adaptor.filter
        if flt && !flt.to_s.empty?
          username = Net::LDAP::Filter.escape(@options[:name_proc].call(username_override || request_data["username"]))
          Net::LDAP::Filter.construct(flt % {username: username})
        else
          Net::LDAP::Filter.equals(adaptor.uid, @options[:name_proc].call(username_override || request_data["username"]))
        end
      end

      # The uid exposed to OmniAuth consumers.
      #
      # This block-based DSL is part of OmniAuth::Strategy; document the value
      # returned by the block.
      #
      # @return [String] the user's uid as determined from the mapped info
      uid { @user_info["uid"] }

      # The `info` hash returned to OmniAuth consumers. Usually contains name, email, etc.
      # @return [Hash<String, Object>]
      info { @user_info }

      # Extra information exposed under `extra[:raw_info]` containing the raw LDAP entry.
      # @return [Hash{Symbol => Object}]
      extra { {raw_info: @ldap_user_info} }

      class << self
        # Map LDAP attributes from the directory entry into a simple Hash used
        # for the OmniAuth `info` hash according to the provided `mapper`.
        #
        # The mapper supports three types of values:
        # - String: a single attribute name. The method will call the attribute
        #   reader (downcased symbol) on the `object` and take the first value.
        # - Array: iterate values and pick the first attribute that exists on the object.
        # - Hash: a mapping of a pattern string to an array of attribute-name lists
        #   where each `%<n>` placeholder in the pattern will be substituted by the
        #   first available attribute from the corresponding list.
        #
        # @param mapper [Hash] mapping configuration (see option :mapping)
        # @param object [#respond_to?, #[]] directory entry (commonly a Net::LDAP::Entry or similar)
        # @return [Hash<String, Object>] the mapped user info hash
        def map_user(mapper, object)
          user = {}
          mapper.each do |key, value|
            case value
            when String
              user[key] = object[value.downcase.to_sym].first if object.respond_to?(value.downcase.to_sym)
            when Array
              value.each do |v|
                if object.respond_to?(v.downcase.to_sym)
                  user[key] = object[v.downcase.to_sym].first
                  break
                end
              end
            when Hash
              value.map do |key1, value1|
                pattern = key1.dup
                value1.each_with_index do |v, i|
                  part = ""
                  v.collect(&:downcase).collect(&:to_sym).each do |v1|
                    if object.respond_to?(v1)
                      part = object[v1].first
                      break
                    end
                  end
                  pattern.gsub!("%#{i}", part || "")
                end
                user[key] = pattern
              end
            else
              # unknown mapping type; ignore
            end
          end
          user
        end
      end

      protected

      # Validate that the incoming request method is allowed.
      #
      # For OmniAuth >= 2.0 the default is POST only. This method checks the
      # Rack env REQUEST_METHOD directly so tests and environments that stub
      # request.HTTP_METHOD are handled deterministically.
      #
      # @return [Boolean] true when the request method is POST
      def valid_request_method?
        request.env["REQUEST_METHOD"] == "POST"
      end

      # Determine if the request is missing required credentials.
      #
      # @return [Boolean] true when username or password are nil/empty
      def missing_credentials?
        request_data["username"].nil? || request_data["username"].empty? || request_data["password"].nil? || request_data["password"].empty?
      end

      # Extract request parameters in a way compatible with Rails/Rack.
      #
      # @return [Hash] parameters hash containing at least "username" and "password" when provided
      def request_data
        @env["action_dispatch.request.request_parameters"] || request.params
      end

      # Extract a normalized username from a trusted header when enabled.
      # Returns nil when not configured or not present.
      #
      # The method will attempt the raw env key (e.g. "REMOTE_USER") and the Rack
      # HTTP_ variant (e.g. "HTTP_REMOTE_USER" or "HTTP_X_REMOTE_USER").
      #
      # @return [String, nil] normalized username or nil if not present
      def header_username
        return unless options[:header_auth]

        name = options[:header_name] || "REMOTE_USER"
        # Try both the raw env var (e.g., REMOTE_USER) and the Rack HTTP_ variant (e.g., HTTP_REMOTE_USER or HTTP_X_REMOTE_USER)
        raw = request.env[name] || request.env["HTTP_#{name.upcase.tr("-", "_")}"]
        return if raw.nil? || raw.to_s.strip.empty?

        options[:name_proc].call(raw.to_s)
      end

      # Perform a directory lookup for the given username using the strategy configuration
      # (bind_dn/password or anonymous). Does not attempt to bind as the user.
      #
      # @param adaptor [OmniAuth::LDAP::Adaptor] initialized adaptor
      # @param username [String] username to look up
      # @return [Object, nil] first directory entry found or nil
      def directory_lookup(adaptor, username)
        entry = nil
        search_filter = filter(adaptor, username)
        adaptor.connection.open do |conn|
          rs = conn.search(filter: search_filter, size: 1)
          entry = rs && rs.first
        end
        entry
      end

      # If the adaptor captured a Password Policy response control, expose a minimal, stable hash
      # in the Rack env for applications to inspect.
      #
      # The structure is available at `request.env['omniauth.ldap.password_policy']`.
      #
      # @param adaptor [OmniAuth::LDAP::Adaptor]
      # @return [void]
      def attach_password_policy_env(adaptor)
        return unless adaptor.respond_to?(:password_policy) && adaptor.password_policy
        ctrl = adaptor.respond_to?(:last_password_policy_response) ? adaptor.last_password_policy_response : nil
        op = adaptor.respond_to?(:last_operation_result) ? adaptor.last_operation_result : nil
        return unless ctrl || op

        request.env["omniauth.ldap.password_policy"] = extract_password_policy(ctrl, op)
      end

      # Best-effort extraction across net-ldap versions; if fields are not available, returns a raw payload.
      #
      # @param control [Object, nil] the password policy response control if available
      # @param operation [Object, nil] the last operation result if available
      # @return [Hash] normalized password policy info with keys :raw, :error, :time_before_expiration, :grace_authns_remaining, :oid, :operation
      def extract_password_policy(control, operation)
        data = {raw: control}
        if control
          # Prefer named readers if present
          if control.respond_to?(:error)
            data[:error] = control.public_send(:error)
          elsif control.respond_to?(:ppolicy_error)
            data[:error] = control.public_send(:ppolicy_error)
          end
          if control.respond_to?(:time_before_expiration)
            data[:time_before_expiration] = control.public_send(:time_before_expiration)
          end
          if control.respond_to?(:grace_authns_remaining)
            data[:grace_authns_remaining] = control.public_send(:grace_authns_remaining)
          elsif control.respond_to?(:grace_logins_remaining)
            data[:grace_authns_remaining] = control.public_send(:grace_logins_remaining)
          end
          if control.respond_to?(:oid)
            data[:oid] = control.public_send(:oid)
          end
        end
        if operation
          code = operation.respond_to?(:code) ? operation.code : nil
          message = operation.respond_to?(:message) ? operation.message : nil
          data[:operation] = {code: code, message: message}
        end
        data
      end
    end
  end
end

OmniAuth.config.add_camelization("ldap", "LDAP")
