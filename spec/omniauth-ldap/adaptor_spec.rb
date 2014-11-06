# frozen_string_literal: true

RSpec.describe OmniAuth::LDAP::Adaptor do
  describe "initialize" do
    it "throws exception when must have field is not set" do
      #[:host, :port, :method, :bind_dn]
      expect {
        described_class.new({host: "192.168.1.145", method: "plain"})
      }.to raise_error(ArgumentError)
    end

    it "throws exception when method is not supported" do
      expect {
        described_class.new({host: "192.168.1.145", method: "myplain", uid: "uid", port: 389, base: "dc=com"})
      }.to raise_error(described_class::ConfigurationError)
    end

    it "does not throw an error if hosts is set but host and port are not" do
      expect {
        described_class.new(
          hosts: [["192.168.1.145", 389], ["192.168.1.146", 389]],
          encryption: "plain",
          base: "dc=example,dc=com",
          uid: "uid",
        )
      }.not_to raise_error
    end

    it "sets up ldap connection with anonymous" do
      adaptor = described_class.new({host: "192.168.1.145", method: "plain", base: "dc=intridea, dc=com", port: 389, uid: "sAMAccountName"})
      expect(adaptor.connection).not_to be_nil
      expect(adaptor.connection.host).to eq "192.168.1.145"
      expect(adaptor.connection.port).to eq 389
      expect(adaptor.connection.base).to eq "dc=intridea, dc=com"
      expect(adaptor.connection.instance_variable_get(:@auth)).to eq({method: :anonymous, username: nil, password: nil})
    end

    it "sets up ldap connection with simple" do
      adaptor = described_class.new({host: "192.168.1.145", method: "plain", base: "dc=intridea, dc=com", port: 389, uid: "sAMAccountName", bind_dn: "bind_dn", password: "password"})
      expect(adaptor.connection).not_to be_nil
      expect(adaptor.connection.host).to eq "192.168.1.145"
      expect(adaptor.connection.port).to eq 389
      expect(adaptor.connection.base).to eq "dc=intridea, dc=com"
      expect(adaptor.connection.instance_variable_get(:@auth)).to eq({method: :simple, username: "bind_dn", password: "password"})
    end

    it "sets up ldap connection with sasl-md5" do
      adaptor = described_class.new({host: "192.168.1.145", method: "plain", base: "dc=intridea, dc=com", port: 389, uid: "sAMAccountName", try_sasl: true, sasl_mechanisms: ["DIGEST-MD5"], bind_dn: "bind_dn", password: "password"})
      expect(adaptor.connection).not_to be_nil
      expect(adaptor.connection.host).to eq "192.168.1.145"
      expect(adaptor.connection.port).to eq 389
      expect(adaptor.connection.base).to eq "dc=intridea, dc=com"
      expect(adaptor.connection.instance_variable_get(:@auth)[:method]).to eq :sasl
      expect(adaptor.connection.instance_variable_get(:@auth)[:mechanism]).to eq "DIGEST-MD5"
      expect(adaptor.connection.instance_variable_get(:@auth)[:initial_credential]).to eq ""
      expect(adaptor.connection.instance_variable_get(:@auth)[:challenge_response]).not_to be_nil
    end

    it "setups ldap connection with sasl-gss" do
      adaptor = described_class.new({host: "192.168.1.145", method: "plain", base: "dc=intridea, dc=com", port: 389, uid: "sAMAccountName", try_sasl: true, sasl_mechanisms: ["GSS-SPNEGO"], bind_dn: "bind_dn", password: "password"})
      expect(adaptor.connection).not_to be_nil
      expect(adaptor.connection.host).to eq "192.168.1.145"
      expect(adaptor.connection.port).to eq 389
      expect(adaptor.connection.base).to eq "dc=intridea, dc=com"
      expect(adaptor.connection.instance_variable_get(:@auth)[:method]).to eq :sasl
      expect(adaptor.connection.instance_variable_get(:@auth)[:mechanism]).to eq "GSS-SPNEGO"
      expect(adaptor.connection.instance_variable_get(:@auth)[:initial_credential]).to match(/^NTLMSSP/)
      expect(adaptor.connection.instance_variable_get(:@auth)[:challenge_response]).not_to be_nil
    end

    it "sets up a connection with the proper host and port" do
      adapter = described_class.new(
        host: "192.168.1.145",
        encryption: "plain",
        base: "dc=example,dc=com",
        port: 3890,
        uid: "uid",
      )

      expect(adapter.connection.host).to eq("192.168.1.145")
      expect(adapter.connection.port).to eq(3890)
      expect(adapter.connection.hosts).to be_nil
    end

    it "sets up a connection with a enumerable pairs of hosts" do
      adapter = described_class.new(
        hosts: [["192.168.1.145", 636], ["192.168.1.146", 636]],
        encryption: "plain",
        base: "dc=example,dc=com",
        uid: "uid",
      )

      expect(adapter.connection.host).to eq("127.0.0.1")
      expect(adapter.connection.port).to eq(389)
      expect(adapter.connection.hosts).to contain_exactly(["192.168.1.145", 636], ["192.168.1.146", 636])
    end

    context "when encryption is plain" do
      it "sets encryption to nil" do
        adaptor = described_class.new({host: "192.168.1.145", encryption: "plain", base: "dc=intridea, dc=com", port: 389, uid: "sAMAccountName"})
        expect(adaptor.connection.instance_variable_get(:@encryption)).to be_nil
      end
    end

    context "when encryption is ssl" do
      it "sets the encryption method to simple_tls" do
        adaptor = described_class.new({host: "192.168.1.145", encryption: "ssl", base: "dc=intridea, dc=com", port: 389, uid: "sAMAccountName"})
        expect(adaptor.connection.instance_variable_get(:@encryption)).to include method: :simple_tls
      end

      context "when disable_verify_certificates is not specified" do
        it "sets the encryption tls_options to OpenSSL default params" do
          adaptor = described_class.new({host: "192.168.1.145", encryption: "ssl", base: "dc=intridea, dc=com", port: 389, uid: "sAMAccountName"})
          expect(adaptor.connection.instance_variable_get(:@encryption)).to include tls_options: OpenSSL::SSL::SSLContext::DEFAULT_PARAMS
        end
      end

      context "when disable_verify_certificates is true" do
        it "sets the encryption tls_options verify_mode explicitly to verify none" do
          adaptor = described_class.new({host: "192.168.1.145", encryption: "ssl", disable_verify_certificates: true, base: "dc=intridea, dc=com", port: 389, uid: "sAMAccountName"})
          expect(adaptor.connection.instance_variable_get(:@encryption)).to include tls_options: {verify_mode: OpenSSL::SSL::VERIFY_NONE}
        end
      end

      context "when disable_verify_certificates is false" do
        it "sets the encryption tls_options to OpenSSL default params" do
          adaptor = described_class.new({host: "192.168.1.145", encryption: "ssl", disable_verify_certificates: false, base: "dc=intridea, dc=com", port: 389, uid: "sAMAccountName"})
          expect(adaptor.connection.instance_variable_get(:@encryption)).to include tls_options: OpenSSL::SSL::SSLContext::DEFAULT_PARAMS
        end
      end

      context "when tls_options are specified" do
        it "passes the values along with defaults" do
          cert = OpenSSL::X509::Certificate.new
          key = OpenSSL::PKey::RSA.new

          adaptor = described_class.new({host: "192.168.1.145", encryption: "ssl", base: "dc=intridea, dc=com", port: 636, uid: "sAMAccountName", bind_dn: "bind_dn", password: "password", tls_options: {ca_file: "/etc/ca.pem", ssl_version: "TLSv1_2", cert: cert, key: key}})
          expect(adaptor.connection.instance_variable_get(:@encryption)).to include tls_options: OpenSSL::SSL::SSLContext::DEFAULT_PARAMS.merge(ca_file: "/etc/ca.pem", ssl_version: "TLSv1_2", cert: cert, key: key)
        end

        it "does not pass nil or blank values" do
          adaptor = described_class.new({host: "192.168.1.145", encryption: "ssl", base: "dc=intridea, dc=com", port: 636, uid: "sAMAccountName", bind_dn: "bind_dn", password: "password", tls_options: {ca_file: nil, ssl_version: " "}})
          expect(adaptor.connection.instance_variable_get(:@encryption)).to include tls_options: OpenSSL::SSL::SSLContext::DEFAULT_PARAMS
        end
      end

      # DEPRECATED
      context "when ca_file is specified" do
        it "sets the encryption tls_options ca_file" do
          adaptor = described_class.new({host: "192.168.1.145", encryption: "ssl", base: "dc=intridea, dc=com", port: 636, uid: "sAMAccountName", bind_dn: "bind_dn", password: "password", ca_file: "/etc/ca.pem"})
          expect(adaptor.connection.instance_variable_get(:@encryption)).to include tls_options: OpenSSL::SSL::SSLContext::DEFAULT_PARAMS.merge(ca_file: "/etc/ca.pem")
        end
      end

      # DEPRECATED
      context "when ssl_version is specified" do
        it "overwrites the encryption tls_options ssl_version" do
          adaptor = described_class.new({host: "192.168.1.145", encryption: "ssl", base: "dc=intridea, dc=com", port: 636, uid: "sAMAccountName", bind_dn: "bind_dn", password: "password", ssl_version: "TLSv1_2"})
          expect(adaptor.connection.instance_variable_get(:@encryption)).to include tls_options: OpenSSL::SSL::SSLContext::DEFAULT_PARAMS.merge(ssl_version: "TLSv1_2")
        end
      end
    end

    context "when encryption is tls" do
      it "sets the encryption method to start_tls" do
        adaptor = described_class.new({host: "192.168.1.145", encryption: "tls", base: "dc=intridea, dc=com", port: 389, uid: "sAMAccountName"})
        expect(adaptor.connection.instance_variable_get(:@encryption)).to include method: :start_tls
      end

      context "when disable_verify_certificates is not specified" do
        it "sets the encryption tls_options to OpenSSL default params" do
          adaptor = described_class.new({host: "192.168.1.145", encryption: "tls", base: "dc=intridea, dc=com", port: 389, uid: "sAMAccountName"})
          expect(adaptor.connection.instance_variable_get(:@encryption)).to include tls_options: OpenSSL::SSL::SSLContext::DEFAULT_PARAMS
        end
      end

      context "when disable_verify_certificates is true" do
        it "sets the encryption tls_options verify_mode explicitly to verify none" do
          adaptor = described_class.new({host: "192.168.1.145", encryption: "tls", disable_verify_certificates: true, base: "dc=intridea, dc=com", port: 389, uid: "sAMAccountName"})
          expect(adaptor.connection.instance_variable_get(:@encryption)).to include tls_options: {verify_mode: OpenSSL::SSL::VERIFY_NONE}
        end
      end

      context "when disable_verify_certificates is false" do
        it "sets the encryption tls_options to OpenSSL default params" do
          adaptor = described_class.new({host: "192.168.1.145", encryption: "tls", disable_verify_certificates: false, base: "dc=intridea, dc=com", port: 389, uid: "sAMAccountName"})
          expect(adaptor.connection.instance_variable_get(:@encryption)).to include tls_options: OpenSSL::SSL::SSLContext::DEFAULT_PARAMS
        end
      end
    end

    context "when method is set instead of encryption" do
      it "sets the encryption method for backwards-compatibility" do
        adaptor = described_class.new({host: "192.168.1.145", method: "tls", base: "dc=intridea, dc=com", port: 389, uid: "sAMAccountName"})
        expect(adaptor.connection.instance_variable_get(:@encryption)).to include method: :start_tls
      end
    end

    context "when timeouts are configured" do
      it "passes connect_timeout and read_timeout settings to Net::LDAP connection" do
        adaptor = described_class.new(host: "192.168.1.145", encryption: "plain", base: "dc=example,dc=com", port: 389, uid: "uid", connect_timeout: 3, read_timeout: 7)
        expect(adaptor.connection.instance_variable_get(:@connect_timeout)).to eq 3
        expect(adaptor.connection.instance_variable_get(:@read_timeout)).to eq 7
      end

      it "omits timeout settings when not provided" do
        adaptor = described_class.new(host: "192.168.1.145", encryption: "plain", base: "dc=example,dc=com", port: 389, uid: "uid")
        expect(adaptor.connection.instance_variable_get(:@connect_timeout)).to be_nil
        expect(adaptor.connection.instance_variable_get(:@read_timeout)).to be_nil
      end
    end
  end

  describe "bind_as" do
    let(:args) { {filter: Net::LDAP::Filter.eq("sAMAccountName", "username"), password: "password", size: 1} }
    let(:rs) { Struct.new(:dn).new("new dn") }

    it "binds simple" do
      adaptor = described_class.new({host: "192.168.1.126", encryption: "plain", base: "dc=score, dc=local", port: 389, uid: "sAMAccountName", bind_dn: "bind_dn", password: "password"})
      allow(adaptor.connection).to receive(:open).and_yield(adaptor.connection)
      allow(adaptor.connection).to receive(:search).with(args).and_return([rs])
      allow(adaptor.connection).to receive(:bind).with({username: "new dn", password: args[:password], method: :simple}).and_return(true)
      expect(adaptor.bind_as(args)).to eq rs
    end

    it "binds sasl" do
      adaptor = described_class.new({host: "192.168.1.145", encryption: "plain", base: "dc=intridea, dc=com", port: 389, uid: "sAMAccountName", try_sasl: true, sasl_mechanisms: ["GSS-SPNEGO"], bind_dn: "bind_dn", password: "password"})
      allow(adaptor.connection).to receive(:open).and_yield(adaptor.connection)
      allow(adaptor.connection).to receive(:search).with(args).and_return([rs])
      allow(adaptor.connection).to receive(:bind).and_return(true)
      expect(adaptor.bind_as(args)).to eq rs
    end

    context "when password policy is enabled" do
      let(:ppolicy_oid) { "1.3.6.1.4.1.42.2.27.8.5.1" }

      it "adds a Password Policy request control to the bind" do
        adaptor = described_class.new({host: "127.0.0.1", encryption: "plain", base: "dc=example, dc=com", port: 389, uid: "sAMAccountName", bind_dn: "bind_dn", password: "password", password_policy: true})
        expect(adaptor.connection).to receive(:open).and_yield(adaptor.connection)
        expect(adaptor.connection).to receive(:search).with(args).and_return([rs])
        expect(adaptor.connection).to receive(:bind) do |bind_args|
          expect(bind_args).to be_a(Hash)
          expect(bind_args[:controls]).to be_a(Array)
          ctrl = bind_args[:controls].first
          oid = ctrl.respond_to?(:oid) ? ctrl.oid : ctrl[:oid]
          expect(oid).to eq(ppolicy_oid)
          true
        end.and_return(true)
        # Stub operation result with a ppolicy response control
        ctrl = Struct.new(:oid).new(ppolicy_oid)
        op_result = Struct.new(:controls).new([ctrl])
        allow(adaptor.connection).to receive(:get_operation_result).and_return(op_result)

        expect(adaptor.bind_as(args)).to eq rs
        expect(adaptor.last_password_policy_response).not_to be_nil
      end
    end
  end

  describe "password policy support" do
    let(:args) { {filter: Net::LDAP::Filter.eq("sAMAccountName", "u"), password: "p", size: 1} }
    let(:entry) { Struct.new(:dn).new("cn=u,dc=example,dc=com") }
    let(:ppolicy_oid) { "1.3.6.1.4.1.42.2.27.8.5.1" }

    def mock_conn(opts = {})
      search_result = opts[:search_result]
      bind_result = opts.key?(:bind_result) ? opts[:bind_result] : true
      op_result_controls = opts[:op_result_controls] || []

      conn = double("ldap connection")
      allow(conn).to receive(:open).and_yield(conn)
      allow(conn).to receive(:search).with(args).and_return(search_result)
      allow(conn).to receive(:bind) do |bind_args|
        @last_bind_args = bind_args
        bind_result
      end
      op_result = Struct.new(:controls).new(op_result_controls)
      allow(conn).to receive(:get_operation_result).and_return(op_result)
      conn
    end

    it "passes a hash control with Password Policy OID and captures response control" do
      adaptor = described_class.new(host: "127.0.0.1", port: 389, encryption: "plain", base: "dc=example,dc=com", uid: "sAMAccountName", password_policy: true)
      # Response control from server (as a minimal struct exposing oid)
      server_ctrl = Struct.new(:oid).new(ppolicy_oid)
      adaptor.instance_variable_set(:@connection, mock_conn(search_result: [entry], op_result_controls: [server_ctrl]))

      expect(adaptor.bind_as(args)).to eq entry
      expect(@last_bind_args[:controls].first).to include(oid: ppolicy_oid)
      expect(adaptor.last_password_policy_response.oid).to eq(ppolicy_oid)
    end

    it "handles hash-shaped response controls from server" do
      adaptor = described_class.new(host: "127.0.0.1", port: 389, encryption: "plain", base: "dc=example,dc=com", uid: "sAMAccountName", password_policy: true)
      hash_ctrl = {oid: ppolicy_oid}
      adaptor.instance_variable_set(:@connection, mock_conn(search_result: [entry], op_result_controls: [hash_ctrl]))

      expect(adaptor.bind_as(args)).to eq entry
      expect(@last_bind_args[:controls].first).to include(oid: ppolicy_oid)
      expect(adaptor.last_password_policy_response).to eq(hash_ctrl)
    end

    it "attaches controls for SASL binds" do
      adaptor = described_class.new(host: "127.0.0.1", port: 389, encryption: "plain", base: "dc=example,dc=com", uid: "sAMAccountName", try_sasl: true, sasl_mechanisms: ["DIGEST-MD5"], bind_dn: "bind_dn", password: "bind_pw", password_policy: true)
      ctrl = Struct.new(:oid).new(ppolicy_oid)
      adaptor.instance_variable_set(:@connection, mock_conn(search_result: [entry], op_result_controls: [ctrl]))

      expect(adaptor.bind_as(args)).to eq entry
      expect(@last_bind_args).to include(method: :sasl)
      expect(@last_bind_args[:controls].first).to include(oid: ppolicy_oid)
      expect(adaptor.last_password_policy_response.oid).to eq(ppolicy_oid)
    end

    it "should raise a ConnectionError if the bind fails" do
      adaptor = OmniAuth::LDAP::Adaptor.new({host: "192.168.1.126", method: 'plain', base: 'dc=score, dc=local', port: 389, uid: 'sAMAccountName', bind_dn: 'bind_dn', password: 'password'})
      expect(adaptor.connection).to receive(:open).and_yield(adaptor.connection)
      # Net::LDAP#search returns nil if the operation was not successful
      expect(adaptor.connection).to receive(:search).with(args).and_return(nil)
      expect(adaptor.connection).not_to receive(:bind)
      expect { adaptor.bind_as(args) }.to raise_error OmniAuth::LDAP::Adaptor::ConnectionError
    end
  end
end
