# frozen_string_literal: true

RSpec.describe "OmniAuth::Strategies::LDAP" do
  # :title => "My LDAP",
  # :host => '10.101.10.1',
  # :port => 389,
  # :method => :plain,
  # :verify_certificates => true,
  # :base => 'dc=intridea, dc=com',
  # :uid => 'sAMAccountName',
  # :name_proc => Proc.new {|name| name.gsub(/@.*$/,'')}
  # :bind_dn => 'default_bind_dn'
  # :password => 'password'
  class MyLdapProvider < OmniAuth::Strategies::LDAP; end

  let(:app) do
    Rack::Builder.new {
      use OmniAuth::Test::PhonySession
      use MyLdapProvider, name: "ldap", title: "MyLdap Form", host: "192.168.1.145", base: "dc=score, dc=local", name_proc: proc { |name| name.gsub(/@.*$/, "") }
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

    if Gem::Version.new(OmniAuth::VERSION) >= Gem::Version.new("2.0.0")
      it "returns 404" do
        expect(last_response.status).to eq 404
        expect(last_response.body).not_to include("<form")
      end
    else
      it "returns 200 and displays a form on OmniAuth < 2.0" do
        expect(last_response.status).to eq 200
        expect(last_response.body).to include("<form")
      end
    end
  end

  describe "/auth/ldap" do
    let!(:csrf_token) { SecureRandom.base64(32) }
    let(:post_env) { make_env("/auth/ldap", "rack.session" => {csrf: csrf_token}, "rack.input" => StringIO.new("authenticity_token=#{escaped_token}")) }
    let(:escaped_token) { URI.encode_www_form_component(csrf_token, Encoding::UTF_8) }

    before { post "/auth/ldap", nil, post_env }

    def make_env(path = "/auth/ldap", props = {})
      {
        "REQUEST_METHOD" => "POST",
        "PATH_INFO" => path,
        "rack.session" => {},
        "rack.input" => StringIO.new("test=true"),
      }.merge(props)
    end

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
      @adaptor = double(OmniAuth::LDAP::Adaptor, {uid: "ping"})

      allow(@adaptor).to receive(:filter)
      allow(OmniAuth::LDAP::Adaptor).to receive(:new) { @adaptor }
    end

    context "failure" do
      before do
        allow(@adaptor).to receive(:bind_as).and_return(false)
      end

      it "fails with missing_credentials" do
        post("/auth/ldap/callback", {})
        expect(last_response).to be_redirect
        expect(last_response.headers["Location"]).to match(%r{missing_credentials})
      end

      it "redirects to error page" do
        post("/auth/ldap/callback", {username: "ping", password: "password"})

        expect(last_response).to be_redirect
        expect(last_response.headers["Location"]).to match("invalid_credentials")
        expect(last_request.env["omniauth.error"].message).to eq("Invalid credentials for ping")
      end

      it "redirects to error page when there is exception" do
        allow(@adaptor).to receive(:bind_as).and_raise(StandardError.new("connection_error"))
        post("/auth/ldap/callback", {username: "ping", password: "password"})
        expect(last_response).to be_redirect
        expect(last_response.headers["Location"]).to match(%r{ldap_error})
      end

      context "when wrong request method" do
        it "redirects to error page" do
          get("/auth/ldap/callback", {username: "ping", password: "password"})

          expect(last_response).to be_redirect
          expect(last_response.headers["Location"]).to match("invalid_request_method")
        end
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
          post("/auth/ldap/callback", {username: ""})

          expect(last_response).to be_redirect
          expect(last_response.headers["Location"]).to match %r{missing_credentials}
        end
      end

      context "when username is present" do
        context "and password is not preset" do
          it "redirects to error page" do
            post("/auth/ldap/callback", {username: "ping"})

            expect(last_response).to be_redirect
            expect(last_response.headers["Location"]).to match %r{missing_credentials}
          end
        end

        context "and password is empty" do
          it "redirects to error page" do
            post("/auth/ldap/callback", {username: "ping", password: ""})

            expect(last_response).to be_redirect
            expect(last_response.headers["Location"]).to match %r{missing_credentials}
          end
        end
      end

      context "when username and password are present" do
        context "and bind on LDAP server failed" do
          it "redirects to error page" do
            post("/auth/ldap/callback", {username: "ping", password: "password"})

            expect(last_response).to be_redirect
            expect(last_response.headers["Location"]).to match("invalid_credentials")
            expect(last_request.env["omniauth.error"].message).to eq("Invalid credentials for ping")
          end

          context "and filter is set" do
            it "binds with filter" do
              allow(@adaptor).to receive(:filter).and_return("uid=%{username}")
              expect(Net::LDAP::Filter).to receive(:construct).with("uid=ping")
              post("/auth/ldap/callback", {username: "ping", password: "password"})

              expect(last_response).to be_redirect
              expect(last_response.headers["Location"]).to match("invalid_credentials")
              expect(last_request.env["omniauth.error"].message).to eq("Invalid credentials for ping")
            end
          end
        end

        context "and communication with LDAP server caused an exception" do
          before do
            allow(@adaptor).to receive(:bind_as).and_raise(StandardError.new("connection_error"))
          end

          it "redirects to error page" do
            post("/auth/ldap/callback", {username: "ping", password: "password"})

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
        post("/auth/ldap/callback", {username: "ping", password: "password"})
        expect(last_response).not_to be_redirect
      end

      context "and filter is set" do
        it "binds with filter" do
          allow(@adaptor).to receive(:filter).and_return("uid=%{username}")
          expect(Net::LDAP::Filter).to receive(:construct).with("uid=ping")
          post("/auth/ldap/callback", {username: "ping", password: "password"})

          expect(last_response).not_to be_redirect
        end
      end

      it "maps user info to Auth Hash" do
        post("/auth/ldap/callback", {username: "ping", password: "password"})
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

    context "when alternate fields" do
      let(:auth_hash) { last_request.env["omniauth.auth"] }

      before do
        allow(@adaptor).to receive(:filter)
        allow(@adaptor).to receive(:bind_as).and_return(Net::LDAP::Entry.from_single_ldif_string(
          %{dn: cn=ping, dc=intridea, dc=com
userprincipalname: ping@intridea.com
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
        ))
      end

      it "maps user info to Auth Hash" do
        post("/auth/ldap/callback", {username: "ping", password: "password"})
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

  # Validate uid behavior specifically when using sAMAccountName
  describe "uid behavior with sAMAccountName option" do
    let(:app) do
      Rack::Builder.new do
        use OmniAuth::Test::PhonySession
        use MySamaccountnameProvider,
          name: "ldap",
          title: "My LDAP",
          host: "1.2.3.4",
          port: 636,
          method: "ssl",
          base: "ou=snip,dc=snip,dc=example,dc=com",
          uid: "sAMAccountName",
          bind_dn: "snip",
          password: "snip"
        run lambda { |env| [404, {"Content-Type" => "text/plain"}, [env.key?("omniauth.auth").to_s]] }
      end.to_app
    end

    before do
      ldap_strategy = Class.new(OmniAuth::Strategies::LDAP)
      stub_const("MySamaccountnameProvider", ldap_strategy)
      @adaptor = double(OmniAuth::LDAP::Adaptor, {uid: "sAMAccountName"})
      allow(@adaptor).to receive(:filter)
      allow(OmniAuth::LDAP::Adaptor).to receive(:new) { @adaptor }
      # Return an entry that includes sAMAccountName but not uid, so nickname maps from sAMAccountName
      allow(@adaptor).to receive(:bind_as).and_return(
        Net::LDAP::Entry.from_single_ldif_string(
          %{dn: cn=ping, dc=snip, dc=example, dc=com
samaccountname: ping
mail: ping@example.com
givenname: Ping
sn: User
},
        ),
      )
    end

    it "sets auth.uid to the DN (not the sAMAccountName attribute) and maps nickname from sAMAccountName" do
      post("/auth/ldap/callback", {username: "ping", password: "secret"})

      expect(last_response).not_to be_redirect

      auth = last_request.env["omniauth.auth"]
      expect(auth.uid).to eq "cn=ping, dc=snip, dc=example, dc=com"
      expect(auth.info.nickname).to eq "ping" # comes from sAMAccountName
    end
  end
end
