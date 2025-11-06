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
  before do
    ldap_strategy = Class.new(OmniAuth::Strategies::LDAP)
    stub_const("MyLdapProvider", ldap_strategy)
  end

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
      expect(last_response.body).to include("action='http://example.org/auth/ldap/callback'")
    end

    it "has a text field for each of the fields" do
      expect(last_response.body.scan("<input").size).to eq 2
    end

    it "has a label of the form title" do
      expect(last_response.body.scan("MyLdap Form").size).to be > 1
    end

    context "when mounted under a subdirectory" do
      let(:sub_env) do
        make_env("/auth/ldap", {
          "SCRIPT_NAME" => "/subdirectory",
          "rack.session" => {csrf: csrf_token},
          "rack.input" => StringIO.new("authenticity_token=#{escaped_token}"),
        })
      end

      it "renders form with full callback_url including subdirectory" do
        post "/auth/ldap", nil, sub_env
        expect(last_response.status).to eq 200
        expect(last_response.body).to include("action='http://example.org/subdirectory/auth/ldap/callback'")
      end

      it "renders form with full callback_url including nested subdirectory" do
        nested_env = make_env("/auth/ldap", {
          "SCRIPT_NAME" => "/nested/app",
          "rack.session" => {csrf: csrf_token},
          "rack.input" => StringIO.new("authenticity_token=#{escaped_token}"),
        })
        post "/auth/ldap", nil, nested_env
        expect(last_response.status).to eq 200
        expect(last_response.body).to include("action='http://example.org/nested/app/auth/ldap/callback'")
      end
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

            it "supports group restriction filters and applies name_proc" do
              # Complex filter with %{username} placeholder and group membership
              group_filter = "(&(uid=%{username})(memberOf=cn=forum-users,ou=groups,dc=example,dc=com))"
              allow(@adaptor).to receive(:filter).and_return(group_filter)
              # username has a domain part; name_proc on strategy under test strips it
              expect(Net::LDAP::Filter).to receive(:construct).with("(&(uid=alice)(memberOf=cn=forum-users,ou=groups,dc=example,dc=com))")

              post("/auth/ldap/callback", {username: "alice@example.com", password: "password"})

              expect(last_response).to be_redirect
              expect(last_response.headers["Location"]).to match("invalid_credentials")
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

        it "escapes special characters in username when building filter" do
          allow(@adaptor).to receive(:filter).and_return("uid=%{username}")
          # '(' => \28 and ')' => \29 per RFC 4515 escaping
          expect(Net::LDAP::Filter).to receive(:construct).with("uid=al\\28ice\\29")
          post("/auth/ldap/callback", {username: "al(ice)", password: "secret"})
        end

        it "binds with complex group filter and applies name_proc" do
          allow(@adaptor).to receive(:bind_as) {
            Net::LDAP::Entry.from_single_ldif_string(
              %{dn: cn=alice, dc=example, dc=com
uid: alice
},
            )
          }
          allow(@adaptor).to receive(:filter).and_return("(&(uid=%{username})(memberOf=cn=forum-users,ou=groups,dc=example,dc=com))")
          expect(Net::LDAP::Filter).to receive(:construct).with("(&(uid=alice)(memberOf=cn=forum-users,ou=groups,dc=example,dc=com))")

          post("/auth/ldap/callback", {username: "alice@example.com", password: "secret"})
          expect(last_response).not_to be_redirect
          expect(last_request.env["omniauth.auth"].info.nickname).to eq "alice"
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

  # Header-based SSO (REMOTE_USER) support
  describe "trusted header SSO" do
    let(:app) do
      Rack::Builder.new do
        use OmniAuth::Test::PhonySession
        use MyHeaderProvider,
          name: "ldap",
          title: "Header LDAP",
          host: "ldap.example.com",
          base: "dc=example,dc=com",
          uid: "uid",
          header_auth: true,
          header_name: "REMOTE_USER",
          name_proc: proc { |n| n.gsub(/@.*$/, "") }
        run lambda { |env| [404, {"Content-Type" => "text/plain"}, [env.key?("omniauth.auth").to_s]] }
      end.to_app
    end

    before do
      ldap_strategy = Class.new(OmniAuth::Strategies::LDAP)
      stub_const("MyHeaderProvider", ldap_strategy)
      @adaptor = double(OmniAuth::LDAP::Adaptor, {uid: "uid", filter: nil})
      allow(OmniAuth::LDAP::Adaptor).to receive(:new) { @adaptor }
    end

    def connection_returning(entry)
      searcher = double("ldap search conn")
      allow(searcher).to receive(:search).and_return(entry ? [entry] : [])
      conn = double("ldap connection")
      allow(conn).to receive(:open).and_yield(searcher)
      conn
    end

    it "redirects from request phase when header present" do
      env = {"rack.session" => {}, "REQUEST_METHOD" => "POST", "PATH_INFO" => "/auth/ldap", "REMOTE_USER" => "alice"}
      post "/auth/ldap", nil, env
      expect(last_response).to be_redirect
      expect(last_response.headers["Location"]).to eq "http://example.org/auth/ldap/callback"
    end

    it "redirects including subdirectory when header present and app is mounted under a subdirectory" do
      env = {"rack.session" => {}, "REQUEST_METHOD" => "POST", "PATH_INFO" => "/auth/ldap", "SCRIPT_NAME" => "/subdir", "REMOTE_USER" => "alice"}
      post "/auth/ldap", nil, env
      expect(last_response).to be_redirect
      expect(last_response.headers["Location"]).to eq "http://example.org/subdir/auth/ldap/callback"
    end

    it "redirects including nested subdirectory when header present and app is mounted under a nested subdirectory" do
      env = {"rack.session" => {}, "REQUEST_METHOD" => "POST", "PATH_INFO" => "/auth/ldap", "SCRIPT_NAME" => "/nested/app", "REMOTE_USER" => "alice"}
      post "/auth/ldap", nil, env
      expect(last_response).to be_redirect
      expect(last_response.headers["Location"]).to eq "http://example.org/nested/app/auth/ldap/callback"
    end

    it "authenticates on callback without password using REMOTE_USER" do
      entry = Net::LDAP::Entry.from_single_ldif_string(%{dn: cn=alice, dc=example, dc=com
uid: alice
mail: alice@example.com
})
      allow(@adaptor).to receive(:connection).and_return(connection_returning(entry))

      post "/auth/ldap/callback", nil, {"REMOTE_USER" => "alice"}

      expect(last_response).not_to be_redirect
      auth = last_request.env["omniauth.auth"]
      expect(auth.uid).to eq "cn=alice, dc=example, dc=com"
      expect(auth.info.nickname).to eq "alice"
    end

    it "authenticates on callback with HTTP_ header variant" do
      entry = Net::LDAP::Entry.from_single_ldif_string(%{dn: cn=alice, dc=example, dc=com
uid: alice
})
      allow(@adaptor).to receive(:connection).and_return(connection_returning(entry))

      post "/auth/ldap/callback", nil, {"HTTP_REMOTE_USER" => "alice"}
      expect(last_response).not_to be_redirect
      auth = last_request.env["omniauth.auth"]
      expect(auth.info.nickname).to eq "alice"
    end

    it "applies name_proc and filter mapping when provided" do
      # search result
      entry = Net::LDAP::Entry.from_single_ldif_string(%{dn: cn=alice, dc=example, dc=com
        uid: alice
      })
      allow(@adaptor).to receive_messages(
        filter: "uid=%{username}",
        connection: connection_returning(entry),
      )
      expect(Net::LDAP::Filter).to receive(:construct).with("uid=alice").and_call_original

      post "/auth/ldap/callback", nil, {"REMOTE_USER" => "alice@example.com"}
      expect(last_response).not_to be_redirect
    end

    it "escapes special characters in header SSO username when building filter" do
      entry = Net::LDAP::Entry.from_single_ldif_string(%{dn: cn=al\\28ice\\29, dc=example, dc=com
uid: al(ice)
})
      allow(@adaptor).to receive_messages(
        connection: connection_returning(entry),
        filter: "uid=%{username}",
      )
      expect(Net::LDAP::Filter).to receive(:construct).with("uid=al\\28ice\\29").and_call_original

      post "/auth/ldap/callback", nil, {"REMOTE_USER" => "al(ice)"}
      expect(last_response).not_to be_redirect
    end

    it "fails when directory lookup returns no entry" do
      allow(@adaptor).to receive(:connection).and_return(connection_returning(nil))
      post "/auth/ldap/callback", nil, {"REMOTE_USER" => "missing"}
      expect(last_response).to be_redirect
      expect(last_response.headers["Location"]).to match(/invalid_credentials/)
    end

    it "supports complex group filter with %{username} in header SSO path" do
      # Expect that the complex filter string is constructed with the processed username
      expect(Net::LDAP::Filter).to receive(:construct).with("(&(uid=alice)(memberOf=cn=forum-users,ou=groups,dc=example,dc=com))").and_call_original

      entry = Net::LDAP::Entry.from_single_ldif_string(%{dn: cn=alice, dc=example, dc=com
uid: alice
})
      allow(@adaptor).to receive_messages(
        filter: "(&(uid=%{username})(memberOf=cn=forum-users,ou=groups,dc=example,dc=com))",
        connection: connection_returning(entry),
      )

      post "/auth/ldap/callback", nil, {"REMOTE_USER" => "alice@example.com"}
      expect(last_response).not_to be_redirect
    end
  end
end
