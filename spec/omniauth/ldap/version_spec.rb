require "anonymous_loader"
require "omniauth/ldap"
RSpec.describe OmniAuth::LDAP::Version do
  it_behaves_like "a Version module", described_class

  it "is greater than 1.0.0" do
    expect(Gem::Version.new(described_class) >= Gem::Version.new("1.0.0")).to be(true)
  end

  it "has VERSION in parent namespace" do
    expect(OmniAuth::LDAP.const_get("VERSION")).to eq(OmniAuth::LDAP::Version::VERSION)
  end

  it "executes the version file for coverage without redefining constants" do
    paths = [
      File.expand_path("../../../lib/omniauth/ldap/version.rb", __dir__),
      File.expand_path("../../../lib/omniauth/ldap/version_gem.rb", __dir__)
    ].select { |path| File.file?(path) }
    anonymous_namespace = AnonymousLoader.load(files: paths)

    expect(anonymous_namespace::OmniAuth::LDAP::Version::VERSION).to eq(described_class::VERSION)
  end
end
