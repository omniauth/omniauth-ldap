require 'spec_helper'
describe OmniAuth::LDAP::Adaptor do

  describe 'initialize' do
    it 'should throw exception when must have field is not set' do
      #[:host, :port, :encryption, :bind_dn]
      lambda { OmniAuth::LDAP::Adaptor.new({host: "192.168.1.145", encryption: 'plain'})}.should raise_error(ArgumentError)
    end

    it 'should not throw an error if hosts is set but host and port are not' do
      expect {
        described_class.new(
          hosts: [['192.168.1.145', 389], ['192.168.1.146', 389]],
          encryption: 'plain',
          base: 'dc=example,dc=com',
          uid: 'uid'
        )
      }.not_to raise_error(ArgumentError)
    end

    it 'should throw exception when encryption method is not supported' do
      lambda { OmniAuth::LDAP::Adaptor.new({host: "192.168.1.145", encryption: 'myplain', uid: 'uid', port: 389, base: 'dc=com'})}.should raise_error(OmniAuth::LDAP::Adaptor::ConfigurationError)
    end

    it 'should setup ldap connection with anonymous' do
      adaptor = OmniAuth::LDAP::Adaptor.new({host: "192.168.1.145", encryption: 'plain', base: 'dc=intridea, dc=com', port: 389, uid: 'sAMAccountName'})
      adaptor.connection.should_not == nil
      adaptor.connection.host.should == '192.168.1.145'
      adaptor.connection.port.should == 389
      adaptor.connection.base.should == 'dc=intridea, dc=com'
      adaptor.connection.instance_variable_get('@auth').should == {:method => :anonymous, :username => nil, :password => nil}
    end

    it 'should setup ldap connection with simple' do
      adaptor = OmniAuth::LDAP::Adaptor.new({host: "192.168.1.145", encryption: 'plain', base: 'dc=intridea, dc=com', port: 389, uid: 'sAMAccountName', bind_dn: 'bind_dn', password: 'password'})
      adaptor.connection.should_not == nil
      adaptor.connection.host.should == '192.168.1.145'
      adaptor.connection.port.should == 389
      adaptor.connection.base.should == 'dc=intridea, dc=com'
      adaptor.connection.instance_variable_get('@auth').should == {:method => :simple, :username => 'bind_dn', :password => 'password'}
      adaptor.connection.instance_variable_get('@encryption').should == nil
    end

    it 'should setup ldap connection with sasl-md5' do
      adaptor = OmniAuth::LDAP::Adaptor.new({host: "192.168.1.145", encryption: 'plain', base: 'dc=intridea, dc=com', port: 389, uid: 'sAMAccountName', try_sasl: true, sasl_mechanisms: ["DIGEST-MD5"], bind_dn: 'bind_dn', password: 'password'})
      adaptor.connection.should_not == nil
      adaptor.connection.host.should == '192.168.1.145'
      adaptor.connection.port.should == 389
      adaptor.connection.base.should == 'dc=intridea, dc=com'
      adaptor.connection.instance_variable_get('@auth')[:method].should == :sasl
      adaptor.connection.instance_variable_get('@auth')[:mechanism].should == 'DIGEST-MD5'
      adaptor.connection.instance_variable_get('@auth')[:initial_credential].should == ''
      adaptor.connection.instance_variable_get('@auth')[:challenge_response].should_not be_nil
    end

    it 'should setup ldap connection with sasl-gss' do
      adaptor = OmniAuth::LDAP::Adaptor.new({host: "192.168.1.145", encryption: 'plain', base: 'dc=intridea, dc=com', port: 389, uid: 'sAMAccountName', try_sasl: true, sasl_mechanisms: ["GSS-SPNEGO"], bind_dn: 'bind_dn', password: 'password'})
      adaptor.connection.should_not == nil
      adaptor.connection.host.should == '192.168.1.145'
      adaptor.connection.port.should == 389
      adaptor.connection.base.should == 'dc=intridea, dc=com'
      adaptor.connection.instance_variable_get('@auth')[:method].should == :sasl
      adaptor.connection.instance_variable_get('@auth')[:mechanism].should == 'GSS-SPNEGO'
      adaptor.connection.instance_variable_get('@auth')[:initial_credential].should =~ /^NTLMSSP/
      adaptor.connection.instance_variable_get('@auth')[:challenge_response].should_not be_nil
    end

    it 'sets up a connection with the proper host and port' do
      adapter = described_class.new(
        host: '192.168.1.145',
        encryption: 'plain',
        base: 'dc=example,dc=com',
        port: 3890,
        uid: 'uid'
      )

      expect(adapter.connection.host).to eq('192.168.1.145')
      expect(adapter.connection.port).to eq(3890)
      expect(adapter.connection.hosts).to be_nil
    end

    it 'sets up a connection with a enumerable pairs of hosts' do
      adapter = described_class.new(
        hosts: [['192.168.1.145', 636], ['192.168.1.146', 636]],
        encryption: 'plain',
        base: 'dc=example,dc=com',
        uid: 'uid'
      )

      expect(adapter.connection.host).to eq('127.0.0.1')
      expect(adapter.connection.port).to eq(389)
      expect(adapter.connection.hosts).to match_array([['192.168.1.145', 636], ['192.168.1.146', 636]])
    end

    context 'when encryption is plain' do
      it 'should set encryption to nil' do
        adaptor = OmniAuth::LDAP::Adaptor.new({host: "192.168.1.145", encryption: 'plain', base: 'dc=intridea, dc=com', port: 389, uid: 'sAMAccountName'})
        adaptor.connection.instance_variable_get('@encryption').should eq(nil)
      end
    end

    context 'when encryption is ssl' do
      it 'should set the encryption method to simple_tls' do
        adaptor = OmniAuth::LDAP::Adaptor.new({host: "192.168.1.145", encryption: 'ssl', base: 'dc=intridea, dc=com', port: 389, uid: 'sAMAccountName'})
        adaptor.connection.instance_variable_get('@encryption').should include method: :simple_tls
      end

      context 'when disable_verify_certificates is not specified' do
        it 'should set the encryption tls_options to OpenSSL default params' do
          adaptor = OmniAuth::LDAP::Adaptor.new({host: "192.168.1.145", encryption: 'ssl', base: 'dc=intridea, dc=com', port: 389, uid: 'sAMAccountName'})
          adaptor.connection.instance_variable_get('@encryption').should include tls_options: OpenSSL::SSL::SSLContext::DEFAULT_PARAMS
        end
      end

      context 'when disable_verify_certificates is true' do
        it 'should set the encryption tls_options verify_mode explicitly to verify none' do
          adaptor = OmniAuth::LDAP::Adaptor.new({host: "192.168.1.145", encryption: 'ssl', disable_verify_certificates: true, base: 'dc=intridea, dc=com', port: 389, uid: 'sAMAccountName'})
          adaptor.connection.instance_variable_get('@encryption').should include tls_options: { verify_mode: OpenSSL::SSL::VERIFY_NONE }
        end
      end

      context 'when disable_verify_certificates is false' do
        it 'should set the encryption tls_options to OpenSSL default params' do
          adaptor = OmniAuth::LDAP::Adaptor.new({host: "192.168.1.145", encryption: 'ssl', disable_verify_certificates: false, base: 'dc=intridea, dc=com', port: 389, uid: 'sAMAccountName'})
          adaptor.connection.instance_variable_get('@encryption').should include tls_options: OpenSSL::SSL::SSLContext::DEFAULT_PARAMS
        end
      end

      context 'when tls_options are specified' do
        it 'should pass the values along with defaults' do
          cert = OpenSSL::X509::Certificate.new
          key  = OpenSSL::PKey::RSA.new

          adaptor = OmniAuth::LDAP::Adaptor.new({host: "192.168.1.145", encryption: 'ssl', base: 'dc=intridea, dc=com', port: 636, uid: 'sAMAccountName', bind_dn: 'bind_dn', password: 'password', tls_options: { ca_file: '/etc/ca.pem', ssl_version: 'TLSv1_2', cert: cert, key: key }})
          adaptor.connection.instance_variable_get('@encryption').should include tls_options: OpenSSL::SSL::SSLContext::DEFAULT_PARAMS.merge(ca_file: '/etc/ca.pem', ssl_version: 'TLSv1_2', cert: cert, key: key)
        end

        it 'does not pass nil or blank values' do
          adaptor = OmniAuth::LDAP::Adaptor.new({host: "192.168.1.145", encryption: 'ssl', base: 'dc=intridea, dc=com', port: 636, uid: 'sAMAccountName', bind_dn: 'bind_dn', password: 'password', tls_options: { ca_file: nil, ssl_version: ' ' }})
          adaptor.connection.instance_variable_get('@encryption').should include tls_options: OpenSSL::SSL::SSLContext::DEFAULT_PARAMS
        end
      end

      # DEPRECATED
      context 'when ca_file is specified' do
        it 'should set the encryption tls_options ca_file' do
          adaptor = OmniAuth::LDAP::Adaptor.new({host: "192.168.1.145", encryption: 'ssl', base: 'dc=intridea, dc=com', port: 636, uid: 'sAMAccountName', bind_dn: 'bind_dn', password: 'password', ca_file: '/etc/ca.pem'})
          adaptor.connection.instance_variable_get('@encryption').should include tls_options: OpenSSL::SSL::SSLContext::DEFAULT_PARAMS.merge(ca_file: '/etc/ca.pem')
        end
      end

      # DEPRECATED
      context 'when ssl_version is specified' do
        it 'should overwrite the encryption tls_options ssl_version' do
          adaptor = OmniAuth::LDAP::Adaptor.new({host: "192.168.1.145", encryption: 'ssl', base: 'dc=intridea, dc=com', port: 636, uid: 'sAMAccountName', bind_dn: 'bind_dn', password: 'password', ssl_version: 'TLSv1_2'})
          adaptor.connection.instance_variable_get('@encryption').should include tls_options: OpenSSL::SSL::SSLContext::DEFAULT_PARAMS.merge(ssl_version: 'TLSv1_2')
        end
      end
    end

    context 'when encryption is tls' do
      it 'should set the encryption method to start_tls' do
        adaptor = OmniAuth::LDAP::Adaptor.new({host: "192.168.1.145", encryption: 'tls', base: 'dc=intridea, dc=com', port: 389, uid: 'sAMAccountName'})
        adaptor.connection.instance_variable_get('@encryption').should include method: :start_tls
      end

      context 'when disable_verify_certificates is not specified' do
        it 'should set the encryption tls_options to OpenSSL default params' do
          adaptor = OmniAuth::LDAP::Adaptor.new({host: "192.168.1.145", encryption: 'tls', base: 'dc=intridea, dc=com', port: 389, uid: 'sAMAccountName'})
          adaptor.connection.instance_variable_get('@encryption').should include tls_options: OpenSSL::SSL::SSLContext::DEFAULT_PARAMS
        end
      end

      context 'when disable_verify_certificates is true' do
        it 'should set the encryption tls_options verify_mode explicitly to verify none' do
          adaptor = OmniAuth::LDAP::Adaptor.new({host: "192.168.1.145", encryption: 'tls', disable_verify_certificates: true, base: 'dc=intridea, dc=com', port: 389, uid: 'sAMAccountName'})
          adaptor.connection.instance_variable_get('@encryption').should include tls_options: { verify_mode: OpenSSL::SSL::VERIFY_NONE }
        end
      end

      context 'when disable_verify_certificates is false' do
        it 'should set the encryption tls_options to OpenSSL default params' do
          adaptor = OmniAuth::LDAP::Adaptor.new({host: "192.168.1.145", encryption: 'tls', disable_verify_certificates: false, base: 'dc=intridea, dc=com', port: 389, uid: 'sAMAccountName'})
          adaptor.connection.instance_variable_get('@encryption').should include tls_options: OpenSSL::SSL::SSLContext::DEFAULT_PARAMS
        end
      end
    end

    context 'when method is set instead of encryption' do
      it 'should set the encryption method for backwards-compatibility' do
        adaptor = OmniAuth::LDAP::Adaptor.new({host: "192.168.1.145", method: 'tls', base: 'dc=intridea, dc=com', port: 389, uid: 'sAMAccountName'})
        adaptor.connection.instance_variable_get('@encryption').should include method: :start_tls
      end
    end
  end

  describe 'bind_as' do
    let(:args) { {:filter => Net::LDAP::Filter.eq('sAMAccountName', 'username'), :password => 'password', :size => 1} }
    let(:rs) { Struct.new(:dn).new('new dn') }

    it 'should bind simple' do
      adaptor = OmniAuth::LDAP::Adaptor.new({host: "192.168.1.126", encryption: 'plain', base: 'dc=score, dc=local', port: 389, uid: 'sAMAccountName', bind_dn: 'bind_dn', password: 'password'})
      adaptor.connection.should_receive(:open).and_yield(adaptor.connection)
      adaptor.connection.should_receive(:search).with(args).and_return([rs])
      adaptor.connection.should_receive(:bind).with({:username => 'new dn', :password => args[:password], :method => :simple}).and_return(true)
      adaptor.bind_as(args).should == rs
    end

    it 'should bind sasl' do
      adaptor = OmniAuth::LDAP::Adaptor.new({host: "192.168.1.145", encryption: 'plain', base: 'dc=intridea, dc=com', port: 389, uid: 'sAMAccountName', try_sasl: true, sasl_mechanisms: ["GSS-SPNEGO"], bind_dn: 'bind_dn', password: 'password'})
      adaptor.connection.should_receive(:open).and_yield(adaptor.connection)
      adaptor.connection.should_receive(:search).with(args).and_return([rs])
      adaptor.connection.should_receive(:bind).and_return(true)
      adaptor.bind_as(args).should == rs
    end
  end
end
