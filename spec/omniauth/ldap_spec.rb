require "open3"

RSpec.describe OmniAuth::LDAP do
  it "does not define sanitizer top-level namespaces" do
    script = [
      'require "omniauth-ldap"',
      'raise "Auth was defined" if Object.const_defined?(:Auth, false)',
      'raise "AuthSanitizer was defined" if Object.const_defined?(:AuthSanitizer, false)',
    ].join("; ")

    output, status = Open3.capture2e(RbConfig.ruby, "-Ilib", "-e", script)
    expect(status).to be_success, output
  end
end
