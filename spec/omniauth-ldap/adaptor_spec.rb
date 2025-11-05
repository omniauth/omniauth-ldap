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
  end

  describe "bind_as" do
    let(:args) { {filter: Net::LDAP::Filter.eq("sAMAccountName", "username"), password: "password", size: 1} }
    let(:rs) { Struct.new(:dn).new("new dn") }

    it "binds simple" do
      adaptor = described_class.new({host: "192.168.1.126", encryption: "plain", base: "dc=score, dc=local", port: 389, uid: "sAMAccountName", bind_dn: "bind_dn", password: "password"})
      expect(adaptor.connection).to receive(:open).and_yield(adaptor.connection)
      expect(adaptor.connection).to receive(:search).with(args).and_return([rs])
      expect(adaptor.connection).to receive(:bind).with({username: "new dn", password: args[:password], method: :simple}).and_return(true)
      expect(adaptor.bind_as(args)).to eq rs
    end

    it "binds sasl" do
      adaptor = described_class.new({host: "192.168.1.145", encryption: "plain", base: "dc=intridea, dc=com", port: 389, uid: "sAMAccountName", try_sasl: true, sasl_mechanisms: ["GSS-SPNEGO"], bind_dn: "bind_dn", password: "password"})
      expect(adaptor.connection).to receive(:open).and_yield(adaptor.connection)
      expect(adaptor.connection).to receive(:search).with(args).and_return([rs])
      expect(adaptor.connection).to receive(:bind).and_return(true)
      expect(adaptor.bind_as(args)).to eq rs
    end
  end
end
