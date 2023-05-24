require 'spec_helper'
describe "OmniAuth::LDAP::Adaptor" do

  describe 'initialize' do
    it 'should throw exception when must have field is not set' do
      #[:host, :port, :method, :bind_dn]
      expect {
        OmniAuth::LDAP::Adaptor.new({ host: "192.168.1.145", method: 'plain' })
      }.to raise_error(ArgumentError)
    end

    it 'should throw exception when method is not supported' do
      expect {
        OmniAuth::LDAP::Adaptor.new({ host: "192.168.1.145", method: 'myplain', uid: 'uid', port: 389, base: 'dc=com' })
      }.to raise_error(OmniAuth::LDAP::Adaptor::ConfigurationError)
    end

    it 'should setup ldap connection with anonymous' do
      adaptor = OmniAuth::LDAP::Adaptor.new({ host: "192.168.1.145", method: 'plain', base: 'dc=intridea, dc=com', port: 389, uid: 'sAMAccountName' })
      expect(adaptor.connection).to_not be_nil
      expect(adaptor.connection.host).to eq '192.168.1.145'
      expect(adaptor.connection.port).to eq 389
      expect(adaptor.connection.base).to eq 'dc=intridea, dc=com'
      expect(adaptor.connection.instance_variable_get('@auth')).to eq({ method: :anonymous, username: nil, password: nil })
    end

    it 'should setup ldap connection with simple' do
      adaptor = OmniAuth::LDAP::Adaptor.new({ host: "192.168.1.145", method: 'plain', base: 'dc=intridea, dc=com', port: 389, uid: 'sAMAccountName', bind_dn: 'bind_dn', password: 'password' })
      expect(adaptor.connection).to_not be_nil
      expect(adaptor.connection.host).to eq '192.168.1.145'
      expect(adaptor.connection.port).to eq 389
      expect(adaptor.connection.base).to eq 'dc=intridea, dc=com'
      expect(adaptor.connection.instance_variable_get('@auth')).to eq({ method: :simple, username: 'bind_dn', password: 'password' })
    end

    it 'should setup ldap connection with sasl-md5' do
      adaptor = OmniAuth::LDAP::Adaptor.new({ host: "192.168.1.145", method: 'plain', base: 'dc=intridea, dc=com', port: 389, uid: 'sAMAccountName', try_sasl: true, sasl_mechanisms: ["DIGEST-MD5"], bind_dn: 'bind_dn', password: 'password' })
      expect(adaptor.connection).to_not be_nil
      expect(adaptor.connection.host).to eq '192.168.1.145'
      expect(adaptor.connection.port).to eq 389
      expect(adaptor.connection.base).to eq 'dc=intridea, dc=com'
      expect(adaptor.connection.instance_variable_get('@auth')[:method]).to eq :sasl
      expect(adaptor.connection.instance_variable_get('@auth')[:mechanism]).to eq 'DIGEST-MD5'
      expect(adaptor.connection.instance_variable_get('@auth')[:initial_credential]).to eq ''
      expect(adaptor.connection.instance_variable_get('@auth')[:challenge_response]).to_not be_nil
    end

    it 'should setup ldap connection with sasl-gss' do
      adaptor = OmniAuth::LDAP::Adaptor.new({host: "192.168.1.145", method: 'plain', base: 'dc=intridea, dc=com', port: 389, uid: 'sAMAccountName', try_sasl: true, sasl_mechanisms: ["GSS-SPNEGO"], bind_dn: 'bind_dn', password: 'password'})
      expect(adaptor.connection).to_not be_nil
      expect(adaptor.connection.host).to eq '192.168.1.145'
      expect(adaptor.connection.port).to eq 389
      expect(adaptor.connection.base).to eq 'dc=intridea, dc=com'
      expect(adaptor.connection.instance_variable_get('@auth')[:method]).to eq :sasl
      expect(adaptor.connection.instance_variable_get('@auth')[:mechanism]).to eq 'GSS-SPNEGO'
      expect(adaptor.connection.instance_variable_get('@auth')[:initial_credential]).to match /^NTLMSSP/
      expect(adaptor.connection.instance_variable_get('@auth')[:challenge_response]).to_not be_nil
    end

    it 'should set the encryption method correctly' do
      adaptor = OmniAuth::LDAP::Adaptor.new({ host: "192.168.1.145", method: 'tls', base: 'dc=intridea, dc=com', port: 389, uid: 'sAMAccountName' })
      expect(adaptor.connection.instance_variable_get('@encryption')).to include method: :start_tls
    end
  end

  describe 'bind_as' do
    let(:args) { { :filter => Net::LDAP::Filter.eq('sAMAccountName', 'username'), :password => 'password', :size => 1 } }
    let(:rs) { Struct.new(:dn).new('new dn') }

    it 'should bind simple' do
      adaptor = OmniAuth::LDAP::Adaptor.new({ host: "192.168.1.126", method: 'plain', base: 'dc=score, dc=local', port: 389, uid: 'sAMAccountName', bind_dn: 'bind_dn', password: 'password' })
      expect(adaptor.connection).to receive(:open).and_yield(adaptor.connection)
      expect(adaptor.connection).to receive(:search).with(args).and_return([rs])
      expect(adaptor.connection).to receive(:bind).with({ :username => 'new dn', :password => args[:password], :method => :simple }).and_return(true)
      expect(adaptor.bind_as(args)).to eq rs
    end

    it 'should bind sasl' do
      adaptor = OmniAuth::LDAP::Adaptor.new({ host: "192.168.1.145", method: 'plain', base: 'dc=intridea, dc=com', port: 389, uid: 'sAMAccountName', try_sasl: true, sasl_mechanisms: ["GSS-SPNEGO"], bind_dn: 'bind_dn', password: 'password' })
      expect(adaptor.connection).to receive(:open).and_yield(adaptor.connection)
      expect(adaptor.connection).to receive(:search).with(args).and_return([rs])
      expect(adaptor.connection).to receive(:bind).and_return(true)
      expect(adaptor.bind_as(args)).to eq rs
    end

    it "should raise a ConnectionError if the bind fails" do
      adaptor = OmniAuth::LDAP::Adaptor.new({host: "192.168.1.126", method: 'plain', base: 'dc=score, dc=local', port: 389, uid: 'sAMAccountName', bind_dn: 'bind_dn', password: 'password'})
      adaptor.connection.should_receive(:open).and_yield(adaptor.connection)
      # Net::LDAP#search returns nil if the operation was not successful
      adaptor.connection.should_receive(:search).with(args).and_return(nil)
      adaptor.connection.should_receive(:bind).never
      lambda { adaptor.bind_as(args) }.should raise_error OmniAuth::LDAP::Adaptor::ConnectionError
    end
  end
end
