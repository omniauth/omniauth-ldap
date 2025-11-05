# frozen_string_literal: true

RSpec.describe OmniAuth::LDAP::Adaptor do
  let(:valid_config) { {host: "127.0.0.1", port: 389, method: "plain", uid: "uid", base: "dc=test,dc=local"} }

  describe ".validate" do
    it "raises ArgumentError when required keys are missing" do
      expect { described_class.validate({}) }.to raise_error(ArgumentError)
    end
  end

  describe "internal helpers" do
    subject { described_class.new(valid_config) }

    it "raises ConfigurationError for unsupported connect method" do
      expect { subject.send(:ensure_method, :bogus) }.to raise_error(OmniAuth::LDAP::Adaptor::ConfigurationError)
    end

    it "returns empty array for no sasl mechanisms" do
      expect(subject.send(:sasl_auths, {sasl_mechanisms: []})).to eq([])
    end

    it "maps ssl/tls to Net::LDAP encryption symbols" do
      expect(subject.send(:ensure_method, "ssl")).to eq(OmniAuth::LDAP::Adaptor::METHOD[:ssl])
      expect(subject.send(:ensure_method, "tls")).to eq(OmniAuth::LDAP::Adaptor::METHOD[:tls])
      expect(subject.send(:ensure_method, "plain")).to eq(OmniAuth::LDAP::Adaptor::METHOD[:plain])
    end

    it "initializes with try_sasl and sets bind_method to :sasl" do
      # Provide an explicit sasl_mechanisms array (empty) so initialize won't call sasl_auths on nil
      a = described_class.new(valid_config.merge(try_sasl: true, sasl_mechanisms: []))
      expect(a.instance_variable_get(:@bind_method)).to eq(:sasl)
    end

    it "initializes with allow_anonymous when no bind_dn/password and sets bind_method to :anonymous" do
      a = described_class.new(valid_config.merge(bind_dn: nil, password: nil))
      expect(a.instance_variable_get(:@bind_method)).to eq(:anonymous)
    end

    it "sasl_auths calls the private setup methods for known mechanisms" do
      # Stub the two private setup methods so we don't exercise heavy external logic
      allow_any_instance_of(described_class).to receive(:sasl_bind_setup_digest_md5).and_return(["ic", proc {}])
      allow_any_instance_of(described_class).to receive(:sasl_bind_setup_gss_spnego).and_return(["i2", proc {}])

      a = described_class.new(valid_config.merge(sasl_mechanisms: ["DIGEST-MD5", "GSS-SPNEGO"]))
      auths = a.send(:sasl_auths, {sasl_mechanisms: ["DIGEST-MD5", "GSS-SPNEGO"]})

      expect(auths).to be_an(Array)
      expect(auths.map { |h| h[:mechanism] }).to include("DIGEST-MD5", "GSS-SPNEGO")
    end

    it "sasl_bind_setup_gss_spnego raises LdapError when missing credentials" do
      a = described_class.new(valid_config)
      expect { a.send(:sasl_bind_setup_gss_spnego, {}) }.to raise_error(OmniAuth::LDAP::Adaptor::LdapError)
    end

    it "sasl_bind_setup_digest_md5 challenge_response returns expected data" do
      # Stub SASL::Preferences and SASL to avoid external dependencies
      pref_double = double("pref")
      sasl_double = double("sasl")
      allow(SASL::Preferences).to receive(:new).and_return(pref_double)
      allow(SASL).to receive(:new).with("DIGEST-MD5", pref_double).and_return(sasl_double)
      allow(sasl_double).to receive(:receive).with("challenge", anything).and_return([nil, "digest_resp"])

      a = described_class.new(valid_config)
      initial, proc_obj = a.send(:sasl_bind_setup_digest_md5, {username: "cn", password: "pw"})
      expect(initial).to eq("")
      expect(proc_obj.call("challenge-data")).to eq("digest_resp")
    end

    it "sasl_bind_setup_gss_spnego returns type1 and proc producing serialized response" do
      # Stub Net::NTLM parsing and Type1 serialization
      t2 = double("t2")
      t3 = double("t3", serialize: "serialized")
      allow(Net::NTLM::Message).to receive(:parse).and_return(t2)
      allow(t2).to receive(:response).and_return(t3)
      allow(t2).to receive(:target_name=)
      # Stub encode_utf16le helper used by the adaptor
      allow(Net::NTLM).to receive(:encode_utf16le).and_return("encoded-domain")
      allow_any_instance_of(Net::NTLM::Message::Type1).to receive(:serialize).and_return("type1")

      a = described_class.new(valid_config)
      type1, proc_obj = a.send(:sasl_bind_setup_gss_spnego, {username: 'user\\DOMAIN', password: "pw"})
      expect(type1).to eq("type1")
      expect(proc_obj.call("challenge")).to eq("serialized")
    end
  end
end
