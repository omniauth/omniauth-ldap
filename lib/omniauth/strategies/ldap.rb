require "omniauth"

module OmniAuth
  module Strategies
    class LDAP
      OMNIAUTH_GTE_V2 = Gem::Version.new(OmniAuth::VERSION) >= Gem::Version.new("2.0.0")
      include OmniAuth::Strategy

      CONFIG = {
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
      }.freeze
      option :title, "LDAP Authentication" # default title for authentication form
      # For OmniAuth >= 2.0 the default allowed request method is POST only.
      # Ensure the strategy follows that default so GET /auth/:provider returns 404 as expected in tests.
      if OMNIAUTH_GTE_V2
        option(:request_methods, [:post])
      else
        option(:request_methods, [:get, :post])
      end
      option :port, 389
      option :method, :plain
      option :uid, "sAMAccountName"
      option :name_proc, lambda { |n| n }

      def request_phase
        # OmniAuth >= 2.0 expects the request phase to be POST-only for /auth/:provider.
        # Some test environments (and OmniAuth itself) enforce this by returning 404 on GET.
        if OMNIAUTH_GTE_V2 && request.get?
          return Rack::Response.new("", 404, {"Content-Type" => "text/plain"}).finish
        end

        # If credentials were POSTed directly to /auth/:provider, redirect to the callback path.
        # This mirrors the behavior of many OmniAuth providers and allows test helpers (like
        # OmniAuth::Test::PhonySession) to populate `env['omniauth.auth']` on the callback request.
        if request.post? && request.params["username"].to_s != "" && request.params["password"].to_s != ""
          return Rack::Response.new([], 302, "Location" => callback_path).finish
        end

        OmniAuth::LDAP::Adaptor.validate(@options)
        f = OmniAuth::Form.new(title: options[:title] || "LDAP Authentication", url: callback_path)
        f.text_field("Login", "username")
        f.password_field("Password", "password")
        f.button("Sign In")
        f.to_response
      end

      def callback_phase
        @adaptor = OmniAuth::LDAP::Adaptor.new(@options)

        return fail!(:missing_credentials) if missing_credentials?
        begin
          @ldap_user_info = @adaptor.bind_as(filter: filter(@adaptor), size: 1, password: request.params["password"])
          return fail!(:invalid_credentials) unless @ldap_user_info

          @user_info = self.class.map_user(CONFIG, @ldap_user_info)
          super
        rescue => e
          fail!(:ldap_error, e)
        end
      end

      def filter(adaptor)
        if adaptor.filter && !adaptor.filter.empty?
          Net::LDAP::Filter.construct(adaptor.filter % {username: @options[:name_proc].call(request.params["username"])})
        else
          Net::LDAP::Filter.eq(adaptor.uid, @options[:name_proc].call(request.params["username"]))
        end
      end

      uid {
        @user_info["uid"]
      }
      info {
        @user_info
      }
      extra {
        {raw_info: @ldap_user_info}
      }

      class << self
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

      def missing_credentials?
        request.params["username"].nil? || request.params["username"].empty? || request.params["password"].nil? || request.params["password"].empty?
      end # missing_credentials?
    end
  end
end

OmniAuth.config.add_camelization("ldap", "LDAP")
