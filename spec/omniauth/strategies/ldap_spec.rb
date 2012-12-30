require 'spec_helper'

describe "OmniAuth::Strategies::LDAP" do
  # :title => "My LDAP",
  # :host => '10.101.10.1',
  # :port => 389,
  # :method => :plain,
  # :base => 'dc=intridea, dc=com',
  # :uid => 'sAMAccountName',
  # :name_proc => Proc.new {|name| name.gsub(/@.*$/,'')}
  # :bind_dn => 'default_bind_dn'
  # :password => 'password'
  class MyLdapProvider < OmniAuth::Strategies::LDAP; end

  def app
    Rack::Builder.new {
      use OmniAuth::Test::PhonySession
      use MyLdapProvider, :name => 'ldap', :title => 'MyLdap Form', :host => '192.168.1.145', :base => 'dc=score, dc=local', :name_proc => Proc.new {|name| name.gsub(/@.*$/,'')}
      run lambda { |env| [404, {'Content-Type' => 'text/plain'}, [env.key?('omniauth.auth').to_s]] }
    }.to_app
  end

  def session
    last_request.env['rack.session']
  end

  it 'should add a camelization for itself' do
    OmniAuth::Utils.camelize('ldap').should == 'LDAP'
  end

  describe '/auth/ldap' do
    before(:each){ get '/auth/ldap' }

    it 'should display a form' do
      last_response.status.should == 200
      last_response.body.should be_include("<form")
    end

    it 'should have the callback as the action for the form' do
      last_response.body.should be_include("action='/auth/ldap/callback'")
    end

    it 'should have a text field for each of the fields' do
      last_response.body.scan('<input').size.should == 2
    end
    it 'should have a label of the form title' do
      last_response.body.scan('MyLdap Form').size.should > 1
    end

  end

  describe 'post /auth/ldap/callback' do
    before(:each) do
      @adaptor = mock(OmniAuth::LDAP::Adaptor, {:uid => 'ping'})
      OmniAuth::LDAP::Adaptor.stub(:new).and_return(@adaptor)
    end

    context 'failure' do
      before(:each) do
        @adaptor.stub(:bind_as).and_return(false)
      end

      it 'should raise MissingCredentialsError' do
        post('/auth/ldap/callback', {})
        last_response.should be_redirect
        last_response.headers['Location'].should =~ %r{ldap_error}
      end

      it 'should redirect to error page' do
        post('/auth/ldap/callback', {:username => 'ping', :password => 'password'})
        last_response.should be_redirect
        last_response.headers['Location'].should =~ %r{invalid_credentials}
      end

      it 'should redirect to error page when there is exception' do
        @adaptor.stub(:bind_as).and_throw(Exception.new('connection_error'))
        post('/auth/ldap/callback', {:username => 'ping', :password => 'password'})
        last_response.should be_redirect
        last_response.headers['Location'].should =~ %r{ldap_error}
      end
    end

    context 'success' do
      let(:auth_hash){ last_request.env['omniauth.auth'] }
      before(:each) do
        @adaptor.stub(:bind_as).and_return({:dn => ['cn=ping, dc=intridea, dc=com'], :mail => ['ping@intridea.com'], :givenname => ['Ping'], :sn => ['Yu'],
                                           :telephonenumber => ['555-555-5555'], :mobile => ['444-444-4444'], :uid => ['ping'], :title => ['dev'], :address =>[ 'k street'],
                                           :l => ['Washington'], :st => ['DC'], :co => ["U.S.A"], :postofficebox => ['20001'], :wwwhomepage => ['www.intridea.com'],
                                           :jpegphoto => ['http://www.intridea.com/ping.jpg'], :description => ['omniauth-ldap']})
        post('/auth/ldap/callback', {:username => 'ping', :password => 'password'})
      end

      it 'should raise MissingCredentialsError' do
        should_not raise_error OmniAuth::Strategies::LDAP::MissingCredentialsError
      end
      it 'should map user info' do
        auth_hash.uid.should == 'cn=ping, dc=intridea, dc=com'
        auth_hash.info.email.should == 'ping@intridea.com'
        auth_hash.info.first_name.should == 'Ping'
        auth_hash.info.last_name.should == 'Yu'
        auth_hash.info.phone.should == '555-555-5555'
        auth_hash.info.mobile.should == '444-444-4444'
        auth_hash.info.nickname.should == 'ping'
        auth_hash.info.title.should == 'dev'
        auth_hash.info.location.should == 'k street, Washington, DC, U.S.A 20001'
        auth_hash.info.url.should == 'www.intridea.com'
        auth_hash.info.image.should == 'http://www.intridea.com/ping.jpg'
        auth_hash.info.description.should == 'omniauth-ldap'
      end
    end
  end
end
