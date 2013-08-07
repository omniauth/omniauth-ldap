require 'spec_helper'
describe "OmniAuth::LDAP::Adaptor" do

  describe 'initialize' do
    it 'should throw exception when must have field is not set' do
      #[:host, :port, :method, :bind_dn]
      lambda { OmniAuth::LDAP::Adaptor.new({host: "192.168.1.145", method: 'plain'})}.should raise_error(ArgumentError)
    end

    it 'should throw exception when method is not supported' do
      lambda { OmniAuth::LDAP::Adaptor.new({host: "192.168.1.145", method: 'myplain', uid: 'uid', port: 389, base: 'dc=com'})}.should raise_error(OmniAuth::LDAP::Adaptor::ConfigurationError)
    end

    it 'should setup ldap connection with anonymous' do
      adaptor = OmniAuth::LDAP::Adaptor.new({host: "192.168.1.145", method: 'plain', base: 'dc=intridea, dc=com', port: 389, uid: 'sAMAccountName'})
      adaptor.connections.first.should_not == nil
      adaptor.connections.first.host.should == '192.168.1.145'
      adaptor.connections.first.port.should == 389
      adaptor.connections.first.base.should == 'dc=intridea, dc=com'
      adaptor.connections.first.instance_variable_get('@auth').should == {:method => :anonymous, :username => nil, :password => nil}
    end

    it 'should setup ldap connection with simple' do
      adaptor = OmniAuth::LDAP::Adaptor.new({host: "192.168.1.145", method: 'plain', base: 'dc=intridea, dc=com', port: 389, uid: 'sAMAccountName', bind_dn: 'bind_dn', password: 'password'})
      adaptor.connections.first.should_not == nil
      adaptor.connections.first.host.should == '192.168.1.145'
      adaptor.connections.first.port.should == 389
      adaptor.connections.first.base.should == 'dc=intridea, dc=com'
      adaptor.connections.first.instance_variable_get('@auth').should == {:method => :simple, :username => 'bind_dn', :password => 'password'}
    end

    it 'should setup ldap connection with sasl-md5' do
      adaptor = OmniAuth::LDAP::Adaptor.new({host: "192.168.1.145", method: 'plain', base: 'dc=intridea, dc=com', port: 389, uid: 'sAMAccountName', try_sasl: true, sasl_mechanisms: ["DIGEST-MD5"], bind_dn: 'bind_dn', password: 'password'})
      adaptor.connections.first.should_not == nil
      adaptor.connections.first.host.should == '192.168.1.145'
      adaptor.connections.first.port.should == 389
      adaptor.connections.first.base.should == 'dc=intridea, dc=com'
      adaptor.connections.first.instance_variable_get('@auth')[:method].should == :sasl
      adaptor.connections.first.instance_variable_get('@auth')[:mechanism].should == 'DIGEST-MD5'
      adaptor.connections.first.instance_variable_get('@auth')[:initial_credential].should == ''
      adaptor.connections.first.instance_variable_get('@auth')[:challenge_response].should_not be_nil
    end

    it 'should setup ldap connection with sasl-gss' do
      adaptor = OmniAuth::LDAP::Adaptor.new({host: "192.168.1.145", method: 'plain', base: 'dc=intridea, dc=com', port: 389, uid: 'sAMAccountName', try_sasl: true, sasl_mechanisms: ["GSS-SPNEGO"], bind_dn: 'bind_dn', password: 'password'})
      adaptor.connections.first.should_not == nil
      adaptor.connections.first.host.should == '192.168.1.145'
      adaptor.connections.first.port.should == 389
      adaptor.connections.first.base.should == 'dc=intridea, dc=com'
      adaptor.connections.first.instance_variable_get('@auth')[:method].should == :sasl
      adaptor.connections.first.instance_variable_get('@auth')[:mechanism].should == 'GSS-SPNEGO'
      adaptor.connections.first.instance_variable_get('@auth')[:initial_credential].should =~ /^NTLMSSP/
      adaptor.connections.first.instance_variable_get('@auth')[:challenge_response].should_not be_nil
    end

    it 'should authenticate against multiple hosts' do
      adaptor = OmniAuth::LDAP::Adaptor.new({host: ["192.168.1.145", "192.168.2.150"], method: 'plain', base: 'dc=intridea, dc=com', port: 389, uid: 'sAMAccountName', bind_dn: 'bind_dn', password: 'password'})
      adaptor.connections.size.should == 2
      adaptor.connections.each do |connection|
        connection.should_not == nil
        %w(192.168.1.145 192.168.2.150).should be_include(connection.host)
        connection.port.should == 389
        connection.base.should == 'dc=intridea, dc=com'
      end
    end
  end

  describe 'bind_as' do
    let(:args) { {:filter => Net::LDAP::Filter.eq('sAMAccountName', 'username'), :password => 'password', :size => 1} }
    let(:rs) { Struct.new(:dn).new('new dn') }

    it 'should bind simple' do
      adaptor = OmniAuth::LDAP::Adaptor.new({host: "192.168.1.126", method: 'plain', base: 'dc=score, dc=local', port: 389, uid: 'sAMAccountName', bind_dn: 'bind_dn', password: 'password'})
      adaptor.connections.each_with_index {|c,i| c.should_receive(:open).and_yield(adaptor.connections[i]) }
      adaptor.connections.each {|c| c.should_receive(:search).with(args).and_return([rs]) }
      adaptor.connections.each {|c| c.should_receive(:bind).with({:username => 'new dn', :password => args[:password], :method => :simple}).and_return(true) }
      adaptor.bind_as(args).should == rs
    end

    it 'should bind sasl' do
      adaptor = OmniAuth::LDAP::Adaptor.new({host: "192.168.1.145", method: 'plain', base: 'dc=intridea, dc=com', port: 389, uid: 'sAMAccountName', try_sasl: true, sasl_mechanisms: ["GSS-SPNEGO"], bind_dn: 'bind_dn', password: 'password'})
      adaptor.connections.each_with_index {|c,i| c.should_receive(:open).and_yield(adaptor.connections[i]) }
      adaptor.connections.each {|c| c.should_receive(:search).with(args).and_return([rs]) }
      adaptor.connections.each {|c| c.should_receive(:bind).and_return(true) }
      adaptor.bind_as(args).should == rs
    end

    it 'should bind for each host' do
      adaptor = OmniAuth::LDAP::Adaptor.new({host: ["192.168.1.145", "192.168.2.150"], method: 'plain', base: 'dc=score, dc=local', port: 389, uid: 'sAMAccountName', bind_dn: 'bind_dn', password: 'password'})
      adaptor.connections.first.should_receive(:open).and_yield(adaptor.connections.first)
      adaptor.connections.first.should_receive(:search).with(args).and_return([rs])
      adaptor.connections.first.should_receive(:bind).and_return(true)

      adaptor.connections[1..-1].each_with_index {|c,i| c.should_not_receive(:open) }
      adaptor.connections[1..-1].each {|c| c.should_not_receive(:search).with(args) }
      adaptor.connections[1..-1].each {|c| c.should_not_receive(:bind) }

      adaptor.bind_as(args).should == rs
    end
  end
end
