# frozen_string_literal: true

begin
  require "roda"
rescue LoadError
  # roda not available in this environment; the integration spec will skip
else
  class SampleRodaApp < Roda
    plugin :sessions, secret: "019a50f6-7880-75be-be8e-e147143543bc-ce1b45052f04-d1d3-4f21-b2f1"

    route do |r|
      r.root do
        '<a href="/auth/ldap">Sign in with LDAP</a>'
      end

      r.on "auth" do
        r.on "ldap" do
          r.get "callback" do
            auth = env["omniauth.auth"] || {}
            name = begin
              auth.dig("info", "name")
            rescue
              nil
            end
            "Signed in: #{name}"
          end
        end
      end
    end
  end
end
