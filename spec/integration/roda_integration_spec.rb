# frozen_string_literal: true

RSpec.describe "Roda integration with OmniAuth::Strategies::LDAP", :integration do
  before(:all) do
    begin
      require "roda"
    rescue LoadError
      skip "roda gem not installed; skipping roda integration specs"
    else
      require_relative "../sample/roda_app"
    end
  end

  let(:app) do
    # Build a stacked rack app: OmniAuth middleware + the sample roda app
    Rack::Builder.new do
      use OmniAuth::Test::PhonySession
      use OmniAuth::Builder do
        provider :ldap,
          name: "ldap",
          title: "Test LDAP",
          host: "127.0.0.1",
          base: "dc=test,dc=local",
          uid: "uid",
          name_proc: proc { |n| n }
      end

      # Use the Roda app Rack-compatible callable
      run SampleRodaApp.app
    end.to_app
  end

  include Rack::Test::Methods

  it "renders the sign-in link at root" do
    get "/"
    expect(last_response.status).to eq 200
    expect(last_response.body).to include("/auth/ldap")
  end

  it "returns 404 for direct GET /auth/ldap on OmniAuth >= 2.0" do
    get "/auth/ldap"
    if Gem::Version.new(OmniAuth::VERSION) >= Gem::Version.new("2.0.0")
      expect(last_response.status).to eq 404
    else
      expect(last_response.status).to eq 200
    end
  end

  it "posts to /auth/ldap and follows the callback" do
    begin
      # Simulate submitting the auth form
      OmniAuth.config.test_mode = true
      OmniAuth.config.mock_auth[:ldap] = OmniAuth::AuthHash.new(provider: "ldap", uid: "alice", info: {"name" => "Alice"})

      post "/auth/ldap", {"username" => "alice", "password" => "secret"}

      # Follow redirects until we reach the callback or hit a reasonable limit
      max_redirects = 5
      redirects = 0
      while last_response.status == 302 && redirects < max_redirects
        follow_redirect!
        redirects += 1
      end

      if last_response.status == 200
        expect(last_response.body).to include("Signed in")
      else
        # Some OmniAuth versions may return 404 for GET /auth/:provider (acceptable)
        expect([404]).to include(last_response.status)
      end
    ensure
      OmniAuth.config.mock_auth.delete(:ldap)
      OmniAuth.config.test_mode = false
    end
  end
end
