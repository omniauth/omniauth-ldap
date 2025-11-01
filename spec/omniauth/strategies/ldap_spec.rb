require "spec_helper"
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

  let(:app) do
    Rack::Builder.new {
      use OmniAuth::Test::PhonySession
      use MyLdapProvider, :name => "ldap", :title => "MyLdap Form", :host => "192.168.1.145", :base => "dc=score, dc=local", :name_proc => proc { |name| name.gsub(/@.*$/, "") }
      run lambda { |env| [404, {"Content-Type" => "text/plain"}, [env.key?("omniauth.auth").to_s]] }
    }.to_app
  end

  let(:session) do
    last_request.env["rack.session"]
  end

  it "adds a camelization for itself" do
    expect(OmniAuth::Utils.camelize("ldap")).to eq "LDAP"
  end

  describe "get /auth/ldap" do
    before { get "/auth/ldap" }

    it "returns 404" do
      expect(last_response.status).to eq 404
      expect(last_response.body).not_to include("<form")
    end
  end

  describe "/auth/ldap" do
    before { post("/auth/ldap", {}) }

    it "displays a form" do
      expect(last_response.status).to eq 200
      expect(last_response.body).to include("<form")
    end

    it "has the callback as the action for the form" do
      expect(last_response.body).to include("action='/auth/ldap/callback'")
    end

    it "has a text field for each of the fields" do
      expect(last_response.body.scan("<input").size).to eq 2
    end

    it "has a label of the form title" do
      expect(last_response.body.scan("MyLdap Form").size).to be > 1
    end
  end

  describe "post /auth/ldap/callback" do
    before do
      @adaptor = double(OmniAuth::LDAP::Adaptor, {:uid => "ping"})

      allow(@adaptor).to receive(:filter)
      allow(OmniAuth::LDAP::Adaptor).to receive(:new) { @adaptor }
    end

    context "failure" do
      before do
        allow(@adaptor).to receive(:bind_as).and_return(false)
      end

      context "when username is not preset" do
        it "redirects to error page" do
          post("/auth/ldap/callback", {})

          # expect(last_response).to be redirect
          expect(last_response).to be_redirect
          expect(last_response.headers["Location"]).to match %r{missing_credentials}
        end
      end

      context "when username is empty" do
        it "redirects to error page" do
          post("/auth/ldap/callback", {:username => ""})

          expect(last_response).to be_redirect
          expect(last_response.headers["Location"]).to match %r{missing_credentials}
        end
      end

      context "when username is present" do
        context "and password is not preset" do
          it "redirects to error page" do
            post("/auth/ldap/callback", {:username => "ping"})

            expect(last_response).to be_redirect
            expect(last_response.headers["Location"]).to match %r{missing_credentials}
          end
        end

        context "and password is empty" do
          it "redirects to error page" do
            post("/auth/ldap/callback", {:username => "ping", :password => ""})

            expect(last_response).to be_redirect
            expect(last_response.headers["Location"]).to match %r{missing_credentials}
          end
        end
      end

      context "when username and password are present" do
        context "and bind on LDAP server failed" do
          it "redirects to error page" do
            post("/auth/ldap/callback", {:username => "ping", :password => "password"})

            expect(last_response).to be_redirect
            expect(last_response.headers["Location"]).to match %r{invalid_credentials}
          end

          context "and filter is set" do
            it "binds with filter" do
              allow(@adaptor).to receive(:filter).and_return("uid=%{username}")
              expect(Net::LDAP::Filter).to receive(:construct).with("uid=ping")
              post("/auth/ldap/callback", {:username => "ping", :password => "password"})

              expect(last_response).to be_redirect
              expect(last_response.headers["Location"]).to match %r{invalid_credentials}
            end
          end
        end

        context "and communication with LDAP server caused an exception" do
          before do
            allow(@adaptor).to receive(:bind_as).and_throw(Exception.new("connection_error"))
          end

          it "redirects to error page" do
            post("/auth/ldap/callback", {:username => "ping", :password => "password"})

            expect(last_response).to be_redirect
            expect(last_response.headers["Location"]).to match %r{ldap_error}
          end
        end
      end
    end

    context "success" do
      let(:auth_hash) { last_request.env["omniauth.auth"] }

      before do
        allow(@adaptor).to receive(:filter)
        allow(@adaptor).to receive(:bind_as) {
          Net::LDAP::Entry.from_single_ldif_string(
            %{dn: cn=ping, dc=intridea, dc=com
mail: ping@intridea.com
givenname: Ping
sn: Yu
telephonenumber: 555-555-5555
mobile: 444-444-4444
uid: ping
title: dev
address: k street
l: Washington
st: DC
co: U.S.A
postofficebox: 20001
wwwhomepage: www.intridea.com
jpegphoto: http://www.intridea.com/ping.jpg
description: omniauth-ldap
},
          )
        }
      end

      it "does not redirect to error page" do
        post("/auth/ldap/callback", {:username => "ping", :password => "password"})
        expect(last_response).not_to be_redirect
      end

      context "and filter is set" do
        it "binds with filter" do
          allow(@adaptor).to receive(:filter).and_return("uid=%{username}")
          expect(Net::LDAP::Filter).to receive(:construct).with("uid=ping")
          post("/auth/ldap/callback", {:username => "ping", :password => "password"})

          expect(last_response).not_to be_redirect
        end
      end

      it "maps user info to Auth Hash" do
        post("/auth/ldap/callback", {:username => "ping", :password => "password"})

        expect(auth_hash.uid).to eq "cn=ping, dc=intridea, dc=com"

        info = auth_hash.info

        expect(info.email).to eq "ping@intridea.com"
        expect(info.first_name).to eq "Ping"
        expect(info.last_name).to eq "Yu"
        expect(info.phone).to eq "555-555-5555"
        expect(info.mobile).to eq "444-444-4444"
        expect(info.nickname).to eq "ping"
        expect(info.title).to eq "dev"
        expect(info.location).to eq "k street, Washington, DC, U.S.A 20001"
        expect(info.url).to eq "www.intridea.com"
        expect(info.image).to eq "http://www.intridea.com/ping.jpg"
        expect(info.description).to eq "omniauth-ldap"
      end
    end
  end
end
