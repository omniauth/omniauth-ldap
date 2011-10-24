#this code borrowed pieces from activeldap and net-ldap

require 'rack'
require 'net/ldap'
require 'net/ntlm'
require 'uri'

module OmniAuth
  module LDAP
    class Adaptor
      class LdapError < StandardError; end
      class ConfigurationError < StandardError; end
      class AuthenticationError < StandardError; end
      class ConnectionError < StandardError; end

      VALID_ADAPTER_CONFIGURATION_KEYS = [:host, :port, :method, :bind_dn, :password, :try_sasl, :sasl_mechanisms, :uid, :base, :allow_anonymous]

      MUST_HAVE_KEYS = [:host, :port, :method, :uid, :base]

      METHOD = {
        :ssl => :simple_tls,
        :tls => :start_tls,
        :plain => nil,
      }

      attr_accessor :bind_dn, :password
      attr_reader :connection, :uid, :base

      def initialize(configuration={})
        @disconnected = false
        @bound = false
        @configuration = configuration.dup
        @configuration[:allow_anonymous] ||= false
        @logger = @configuration.delete(:logger)
        message = []
        MUST_HAVE_KEYS.each do |name|
            message << name if configuration[name].nil?
        end
        raise ArgumentError.new(message.join(",") +" MUST be provided") unless message.empty?
        VALID_ADAPTER_CONFIGURATION_KEYS.each do |name|
          instance_variable_set("@#{name}", configuration[name])
        end

        method = ensure_method(@method)
        config = {
          :host => @host,
          :port => @port,
          :encryption => method
        }
        @uri = construct_uri(@host, @port, @method != :plain)
        
        @bind_method = @try_sasl ? "sasl" : @allow_anonymous ? 'anonymous' : 'simple'
        @bind_method = 'anonymous' unless @bind_dn && @password
        
        @auth = sasl_auths.first if @bind_method == 'sasl'
        @bind_method = 'simple' unless @auth
        @auth ||= { :method => @bind_method,
                    :username => @bind_dn,
                    :password => @passowrd
                  }
        config[:auth] = @auth
        @connection = Net::LDAP.new(config)
      end
      
      #:base => "dc=yourcompany, dc=com",
      # :filter => "(mail=#{user})",
      # :password => psw
      def bind_as(args = {})
        result = false
        @connection.open { |me|
          rs = search args
          if rs and rs.first and dn = rs.first.dn
            password = args[:password]
            method = args[:method]
            password = password.call if password.respond_to?(:call)
            if method == 'sasl'
            result = rs if bind(sasl_auths(args))
            else
            result = rs if bind(:method => :simple, :username => dn,
                                :password => password)
            end
          end
        }
        result
      end

      private

      def ensure_port(method)
        if method == :ssl
          URI::LDAPS::DEFAULT_PORT
        else
          URI::LDAP::DEFAULT_PORT
        end
      end

      def ensure_method(method)
          method ||= "plain"
          normalized_method = method.to_s.downcase.to_sym
          return METHOD[normalized_method] if METHOD.has_key?(normalized_method)

          available_methods = METHOD.keys.collect {|m| m.inspect}.join(", ")
          format = "%s is not one of the available connect methods: %s"
          raise ConfigurationError, format % [method.inspect, available_methods]
      end

      def sasl_auths(options={})
        auths = []
        sasl_mechanisms = options[:sasl_mechanisms] || @sasl_mechanisms
        sasl_mechanisms.each do |mechanism|
          normalized_mechanism = mechanism.downcase.gsub(/-/, '_')
          sasl_bind_setup = "sasl_bind_setup_#{normalized_mechanism}"
          next unless respond_to?(sasl_bind_setup, true)
          initial_credential, challenge_response = send(sasl_bind_setup, options)

          auths << {
            :method => :sasl,
            :initial_credential => initial_credential,
            :mechanism => mechanism,
            :challenge_response => challenge_response,
          }
        end
      end

      def sasl_bind_setup_digest_md5(options)
        bind_dn = options[:username]
        initial_credential = ""
        challenge_response = Proc.new do |cred|
          pref = SASL::Preferences.new :digest_uri => "ldap/#{@host}", :username => bind_dn, :has_password? => true, :password => options[:password]||@password
          sasl = SASL.new("DIGEST-MD5", pref)
          response = sasl.receive("challenge", cred)
          response[1]
        end
        [initial_credential, challenge_response]
      end

      def sasl_bind_setup_gss_spnego(options)
        bind_dn = options[:username]
        psw = [bind_dn, options[:password]||@password]
        raise LdapError.new( "invalid binding information" ) unless (bind_dn && psw)

        nego = proc {|challenge|
          t2_msg = Net::NTLM::Message.parse( challenge )
          bind_dn, domain = bind_dn.split('\\').reverse
          t2_msg.target_name = Net::NTLM::encode_utf16le(domain) if domain
          t3_msg = t2_msg.response( {:user => bind_dn, :password => psw}, {:ntlmv2 => true} )
          t3_msg.serialize
        }
        [Net::NTLM::Message::Type1.new.serialize, nego]
      end

      def construct_uri(host, port, ssl)
        protocol = ssl ? "ldaps" : "ldap"
        URI.parse("#{protocol}://#{host}:#{port}").to_s
      end
    end
  end
end
