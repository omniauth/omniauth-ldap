# frozen_string_literal: true

# this code borrowed pieces from activeldap and net-ldap

# External Gems
require "net/ldap"
require "net/ntlm"
require "rack"
require "sasl"

module OmniAuth
  module LDAP
    class Adaptor
      class LdapError < StandardError; end
      class ConfigurationError < StandardError; end
      class AuthenticationError < StandardError; end
      class ConnectionError < StandardError; end

      VALID_ADAPTER_CONFIGURATION_KEYS = [
        :hosts,
        :host,
        :port,
        :encryption,
        :disable_verify_certificates,
        :bind_dn,
        :password,
        :try_sasl,
        :sasl_mechanisms,
        :uid,
        :base,
        :allow_anonymous,
        :filter,
        :tls_options,
        :password_policy,
        # Timeouts
        :connect_timeout,
        :read_timeout,

        # Deprecated
        :method,
        :ca_file,
        :ssl_version,
      ]

      # A list of needed keys. Possible alternatives are specified using sub-lists.
      MUST_HAVE_KEYS = [
        :base,
        [:encryption, :method], # :method is deprecated
        [:hosts, :host],
        [:hosts, :port],
        [:uid, :filter],
      ]

      ENCRYPTION_METHOD = {
        simple_tls: :simple_tls,
        start_tls: :start_tls,
        plain: nil,

        # Deprecated. This mapping aimed to be user-friendly, but only caused
        # confusion. Better to pass through the actual `Net::LDAP` encryption type.
        ssl: :simple_tls,
        tls: :start_tls,
      }

      attr_accessor :bind_dn, :password
      attr_reader :connection, :uid, :base, :auth, :filter, :password_policy, :last_operation_result, :last_password_policy_response

      def self.validate(configuration = {})
        message = []
        MUST_HAVE_KEYS.each do |names|
          names = [names].flatten
          missing_keys = names.select { |name| configuration[name].nil? }
          if missing_keys == names
            message << names.join(" or ")
          end
        end
        raise ArgumentError.new(message.join(",") + " MUST be provided") unless message.empty?
      end

      def initialize(configuration = {})
        Adaptor.validate(configuration)
        @configuration = configuration.dup
        @configuration[:allow_anonymous] ||= false
        @logger = @configuration.delete(:logger)
        VALID_ADAPTER_CONFIGURATION_KEYS.each do |name|
          instance_variable_set("@#{name}", @configuration[name])
        end
        config = {
          base: @base,
          hosts: @hosts,
          host: @host,
          port: @port,
          encryption: encryption_options,
        }
        # Remove passing timeouts here to avoid issues on older net-ldap versions.
        # We'll set them after initialization if the connection responds to writers.
        @bind_method = if @try_sasl
          :sasl
        else
          ((@allow_anonymous || !@bind_dn || !@password) ? :anonymous : :simple)
        end

        @auth = sasl_auths({username: @bind_dn, password: @password}).first if @bind_method == :sasl
        @auth ||= {
          method: @bind_method,
          username: @bind_dn,
          password: @password,
        }
        config[:auth] = @auth
        @connection = Net::LDAP.new(config)
        # Apply optional timeout settings if supported by the installed net-ldap version
        if !@connect_timeout.nil?
          if @connection.respond_to?(:connect_timeout=)
            @connection.connect_timeout = @connect_timeout
          else
            @connection.instance_variable_set(:@connect_timeout, @connect_timeout)
          end
        end
        if !@read_timeout.nil?
          if @connection.respond_to?(:read_timeout=)
            @connection.read_timeout = @read_timeout
          else
            @connection.instance_variable_set(:@read_timeout, @read_timeout)
          end
        end
      end

      #:base => "dc=yourcompany, dc=com",
      # :filter => "(mail=#{user})",
      # :password => psw
      def bind_as(args = {})
        result = false
        @last_operation_result = nil
        @last_password_policy_response = nil
        @connection.open do |me|
          rs = me.search(args)
          if rs && rs.first
            dn = rs.first.dn
            if dn
              password = args[:password]
              password = password.call if password.respond_to?(:call)

              bind_args = if @bind_method == :sasl
                sasl_auths({username: dn, password: password}).first
              else
                {
                  method: :simple,
                  username: dn,
                  password: password,
                }
              end

              # Optionally request LDAP Password Policy control (RFC Draft - de facto standard)
              if @password_policy
                # Always request by OID using a simple hash; avoids depending on gem-specific control classes
                control = {oid: "1.3.6.1.4.1.42.2.27.8.5.1", criticality: true, value: nil}
                if bind_args.is_a?(Hash)
                  bind_args = bind_args.merge({controls: [control]})
                else
                  # Some Net::LDAP versions allow passing a block for SASL only; ensure we still can add controls if hash
                  # When not a Hash, we can't merge; rely on server default behavior.
                end
              end

              begin
                success = bind_args ? me.bind(bind_args) : me.bind
              ensure
                capture_password_policy(me)
              end

              result = rs.first if success
            end
          end
        end
        result
      end

      private

      def encryption_options
        translated_method = translate_method
        return unless translated_method

        {
          method: translated_method,
          tls_options: tls_options(translated_method),
        }
      end

      def translate_method
        method = @encryption || @method
        method ||= "plain"
        normalized_method = method.to_s.downcase.to_sym

        unless ENCRYPTION_METHOD.has_key?(normalized_method)
          available_methods = ENCRYPTION_METHOD.keys.collect { |m| m.inspect }.join(", ")
          format = "%s is not one of the available connect methods: %s"
          raise ConfigurationError, format % [method.inspect, available_methods]
        end

        ENCRYPTION_METHOD[normalized_method]
      end

      def tls_options(translated_method)
        return {} if translated_method.nil? # (plain)

        options = default_options

        if @tls_options
          # Prevent blank config values from overwriting SSL defaults
          configured_options = sanitize_hash_values(@tls_options)
          configured_options = symbolize_hash_keys(configured_options)

          options.merge!(configured_options)
        end

        # Retain backward compatibility until deprecated configs are removed.
        options[:ca_file] = @ca_file if @ca_file
        options[:ssl_version] = @ssl_version if @ssl_version

        options
      end

      def sasl_auths(options = {})
        auths = []
        sasl_mechanisms = options[:sasl_mechanisms] || @sasl_mechanisms
        sasl_mechanisms.each do |mechanism|
          normalized_mechanism = mechanism.downcase.tr("-", "_")
          sasl_bind_setup = "sasl_bind_setup_#{normalized_mechanism}"
          next unless respond_to?(sasl_bind_setup, true)
          initial_credential, challenge_response = send(sasl_bind_setup, options)
          auths << {
            method: :sasl,
            initial_credential: initial_credential,
            mechanism: mechanism,
            challenge_response: challenge_response,
          }
        end
        auths
      end

      def sasl_bind_setup_digest_md5(options)
        bind_dn = options[:username]
        initial_credential = ""
        challenge_response = proc do |cred|
          pref = SASL::Preferences.new(digest_uri: "ldap/#{@host}", username: bind_dn, has_password?: true, password: options[:password])
          sasl = SASL.new("DIGEST-MD5", pref)
          response = sasl.receive("challenge", cred)
          response[1]
        end
        [initial_credential, challenge_response]
      end

      def sasl_bind_setup_gss_spnego(options)
        bind_dn = options[:username]
        psw = options[:password]
        raise LdapError.new("invalid binding information") unless bind_dn && psw

        nego = proc { |challenge|
          t2_msg = Net::NTLM::Message.parse(challenge)
          bind_dn, domain = bind_dn.split("\\").reverse
          t2_msg.target_name = Net::NTLM.encode_utf16le(domain) if domain
          t3_msg = t2_msg.response({user: bind_dn, password: psw}, {ntlmv2: true})
          t3_msg.serialize
        }
        [Net::NTLM::Message::Type1.new.serialize, nego]
      end

      private

      def default_options
        if @disable_verify_certificates
          # It is important to explicitly set verify_mode for two reasons:
          # 1. The behavior of OpenSSL is undefined when verify_mode is not set.
          # 2. The net-ldap gem implementation verifies the certificate hostname
          #    unless verify_mode is set to VERIFY_NONE.
          {verify_mode: OpenSSL::SSL::VERIFY_NONE}
        else
          OpenSSL::SSL::SSLContext::DEFAULT_PARAMS.dup
        end
      end

      # Removes keys that have blank values
      #
      # This gem may not always be in the context of Rails so we
      # do this rather than `.blank?`.
      def sanitize_hash_values(hash)
        hash.delete_if do |_, value|
          value.nil? ||
            (value.is_a?(String) && value !~ /\S/)
        end
      end

      def symbolize_hash_keys(hash)
        hash.each_with_object({}) do |(key, value), result|
          result[key.to_sym] = value
        end
      end

      # Capture the operation result and extract any Password Policy response control if present.
      def capture_password_policy(conn)
        return unless @password_policy
        return unless conn.respond_to?(:get_operation_result)

        begin
          @last_operation_result = conn.get_operation_result
          controls = if @last_operation_result && @last_operation_result.respond_to?(:controls)
            @last_operation_result.controls || []
          else
            []
          end
          if controls.any?
            # Find Password Policy response control by OID
            ppolicy_oid = "1.3.6.1.4.1.42.2.27.8.5.1"
            ctrl = controls.find do |c|
              (c.respond_to?(:oid) && c.oid == ppolicy_oid) || (c.is_a?(Hash) && c[:oid] == ppolicy_oid)
            end
            @last_password_policy_response = ctrl if ctrl
          end
        rescue StandardError
          # Swallow errors to keep authentication flow unaffected when server or gem doesn't support controls
          @last_password_policy_response = nil
        end
      end
    end
  end
end
