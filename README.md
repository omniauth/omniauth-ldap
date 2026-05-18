[![Galtzo FLOSS Logo by Aboling0, CC BY-SA 4.0][🖼️galtzo-i]][🖼️galtzo-discord] [![ruby-lang Logo, Yukihiro Matsumoto, Ruby Visual Identity Team, CC BY-SA 2.5][🖼️ruby-lang-i]][🖼️ruby-lang] [![omniauth Logo (presumed to be) by tomeara, (presumed to be) MIT License][🖼️omniauth-i]][🖼️omniauth]

[🖼️galtzo-i]: https://logos.galtzo.com/assets/images/galtzo-floss/avatar-192px.svg
[🖼️galtzo-discord]: https://discord.gg/3qme4XHNKN
[🖼️ruby-lang-i]: https://logos.galtzo.com/assets/images/ruby-lang/avatar-192px.svg
[🖼️ruby-lang]: https://www.ruby-lang.org/
[🖼️omniauth-i]: https://logos.galtzo.com/assets/images/omniauth/avatar-192px.png
[🖼️omniauth]: https://github.com/omniauth/omniauth-ldap

# 📁 OmniAuth LDAP

[![Version][👽versioni]][👽version] [![GitHub tag (latest SemVer)][⛳️tag-img]][⛳️tag] [![License: MIT][📄license-img]][📄license-ref] [![Downloads Rank][👽dl-ranki]][👽dl-rank] [![Open Source Helpers][👽oss-helpi]][👽oss-help] [![CodeCov Test Coverage][🏀codecovi]][🏀codecov] [![Coveralls Test Coverage][🏀coveralls-img]][🏀coveralls] [![CI Heads][🚎3-hd-wfi]][🚎3-hd-wf] [![CI Runtime Dependencies @ HEAD][🚎12-crh-wfi]][🚎12-crh-wf] [![CI Current][🚎11-c-wfi]][🚎11-c-wf] [![CI Truffle Ruby][🚎9-t-wfi]][🚎9-t-wf] [![CI JRuby][🚎10-j-wfi]][🚎10-j-wf] [![Deps Locked][🚎13-🔒️-wfi]][🚎13-🔒️-wf] [![Deps Unlocked][🚎14-🔓️-wfi]][🚎14-🔓️-wf] [![CI Supported][🚎6-s-wfi]][🚎6-s-wf] [![CI Legacy][🚎4-lg-wfi]][🚎4-lg-wf] [![CI Unsupported][🚎7-us-wfi]][🚎7-us-wf] [![CI Ancient][🚎1-an-wfi]][🚎1-an-wf] [![CI Test Coverage][🚎2-cov-wfi]][🚎2-cov-wf] [![CI Style][🚎5-st-wfi]][🚎5-st-wf] [![CodeQL][🖐codeQL-img]][🖐codeQL] [![Apache SkyWalking Eyes License Compatibility Check][🚎15-🪪-wfi]][🚎15-🪪-wf]

`if ci_badges.map(&:color).detect { it != "green"}` ☝️ [let me know][🖼️galtzo-discord], as I may have missed the [discord notification][🖼️galtzo-discord].

---

`if ci_badges.map(&:color).all? { it == "green"}` 👇️ send money so I can do more of this. FLOSS maintenance is now my full-time job.

[![Sponsor Me on Github][🖇sponsor-img]][🖇sponsor] [![Liberapay Goal Progress][⛳liberapay-img]][⛳liberapay] [![Donate on PayPal][🖇paypal-img]][🖇paypal] [![Buy me a coffee][🖇buyme-small-img]][🖇buyme] [![Donate on Polar][🖇polar-img]][🖇polar] [![Donate at ko-fi.com][🖇kofi-img]][🖇kofi]

<details>
    <summary>👣 How will this project approach the September 2025 hostile takeover of RubyGems? 🚑️</summary>

I've summarized my thoughts in [this blog post](https://dev.to/galtzo/hostile-takeover-of-rubygems-my-thoughts-5hlo).

</details>

## 🌻 Synopsis

Use the LDAP strategy as a middleware in your application:

```ruby
use OmniAuth::Strategies::LDAP,
  title: "My LDAP",
  host: "10.101.10.1",
  port: 389,
  encryption: :plain,
  base: "dc=intridea,dc=com",
  uid: "sAMAccountName",
  name_proc: proc { |name| name.gsub(/@.*$/, "") },
  bind_dn: "default_bind_dn",
  password: "password",
  # Optional timeouts (seconds)
  connect_timeout: 3,
  read_timeout: 7,
  tls_options: {
    ssl_version: "TLSv1_2",
    ciphers: ["AES-128-CBC", "AES-128-CBC-HMAC-SHA1", "AES-128-CBC-HMAC-SHA256"],
  },
  mapping: {
    "name" => "cn;lang-en",
    "email" => ["preferredEmail", "mail"],
    "nickname" => ["uid", "userid", "sAMAccountName"],
  }
# Or, alternatively:
# use OmniAuth::Strategies::LDAP, filter: '(&(uid=%{username})(memberOf=cn=myapp-users,ou=groups,dc=example,dc=com))'
```

At minimum you normally configure `:host`, `:base`, and either `:uid` or `:filter`. The other options shown above customize connection behavior, TLS, username normalization, timeouts, and returned auth info.

For trusted header SSO, enable `header_auth: true` and explicitly choose the trusted identity source with `header_auth_source: :env` or `header_auth_source: :http_header`. See [Trusted header SSO](#trusted-header-sso-remote_user-and-friends) for the security requirements.

### TLS certificate verification

This gem enables TLS certificate verification by default when you use `encryption: "ssl"` (LDAPS / simple TLS) or `encryption: "tls"` (STARTTLS). We always pass `tls_options` to Net::LDAP based on `OpenSSL::SSL::SSLContext::DEFAULT_PARAMS`, which includes `verify_mode: OpenSSL::SSL::VERIFY_PEER` and sane defaults.

- Secure by default: you do not need to set anything extra to verify the LDAP server certificate.
- To customize trust or ciphers, supply your own `tls_options`, which are merged over the safe defaults.
- If you truly need to skip verification (not recommended), set `disable_verify_certificates: true`.

Examples:

```ruby
# Verify server certs (default behavior)
use OmniAuth::Strategies::LDAP,
  host: ENV["LDAP_HOST"],
  port: 636,
  encryption: "ssl",  # or "tls"
  base: "dc=example,dc=com",
  uid:  "uid"

# Use a private CA bundle and restrict protocol/ciphers
use OmniAuth::Strategies::LDAP,
  host: ENV["LDAP_HOST"],
  port: 636,
  encryption: "ssl",
  base: "dc=example,dc=com",
  uid:  "uid",
  tls_options: {
    ca_file: "/etc/ssl/private/my_org_ca.pem",
    ssl_version: "TLSv1_2",
    ciphers: ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"],
  }

# Opt out of verification (NOT recommended – use only in trusted test/dev scenarios)
use OmniAuth::Strategies::LDAP,
  host: ENV["LDAP_HOST"],
  port: 636,
  encryption: "ssl",
  base: "dc=example,dc=com",
  uid:  "uid",
  disable_verify_certificates: true
```

Note: Net::LDAP historically defaulted to no certificate validation when `tls_options` were not provided. This library mitigates that by always providing secure `tls_options` unless you explicitly disable verification.

## 💡 Info you can shake a stick at

| Tokens to Remember      | [![Gem name][⛳️name-img]][⛳️gem-name] [![Gem namespace][⛳️namespace-img]][⛳️gem-namespace]                                                                                                                                                                                                                                                                          |
|-------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Works with JRuby        | ![JRuby 9.1 Compat][💎jruby-9.1i] ![JRuby 9.2 Compat][💎jruby-9.2i] ![JRuby 9.3 Compat][💎jruby-9.3i] <br/> [![JRuby 9.4 Compat][💎jruby-9.4i]][🚎10-j-wf] [![JRuby 10.0 Compat][💎jruby-c-i]][🚎11-c-wf] [![JRuby HEAD Compat][💎jruby-headi]][🚎3-hd-wf]                                                                                                          |
| Works with Truffle Ruby | ![Truffle Ruby 22.3 Compat][💎truby-22.3i] ![Truffle Ruby 23.0 Compat][💎truby-23.0i] <br/> [![Truffle Ruby 23.1 Compat][💎truby-23.1i]][🚎9-t-wf] [![Truffle Ruby 24.1 Compat][💎truby-c-i]][🚎11-c-wf]                                                                                                                                                            |
| Works with MRI Ruby 3   | [![Ruby 3.0 Compat][💎ruby-3.0i]][🚎4-lg-wf] [![Ruby 3.1 Compat][💎ruby-3.1i]][🚎6-s-wf] [![Ruby 3.2 Compat][💎ruby-3.2i]][🚎6-s-wf] [![Ruby 3.3 Compat][💎ruby-3.3i]][🚎6-s-wf] [![Ruby 3.4 Compat][💎ruby-c-i]][🚎11-c-wf] [![Ruby HEAD Compat][💎ruby-headi]][🚎3-hd-wf]                                                                                         |
| Works with MRI Ruby 2   | ![Ruby 2.0 Compat][💎ruby-2.0i] ![Ruby 2.1 Compat][💎ruby-2.1i] ![Ruby 2.2 Compat][💎ruby-2.2i] <br/> [![Ruby 2.3 Compat][💎ruby-2.3i]][🚎1-an-wf] [![Ruby 2.4 Compat][💎ruby-2.4i]][🚎1-an-wf] [![Ruby 2.5 Compat][💎ruby-2.5i]][🚎1-an-wf] [![Ruby 2.6 Compat][💎ruby-2.6i]][🚎7-us-wf] [![Ruby 2.7 Compat][💎ruby-2.7i]][🚎7-us-wf]                              |
| Support & Community     | [![Join Me on Daily.dev's RubyFriends][✉️ruby-friends-img]][✉️ruby-friends] [![Live Chat on Discord][✉️discord-invite-img-ftb]][✉️discord-invite] [![Get help from me on Upwork][👨🏼‍🏫expsup-upwork-img]][👨🏼‍🏫expsup-upwork] [![Get help from me on Codementor][👨🏼‍🏫expsup-codementor-img]][👨🏼‍🏫expsup-codementor]                                       |
| Source                  | [![Source on Github.com][📜src-gh-img]][📜src-gh] [![The best SHA: dQw4w9WgXcQ!][🧮kloc-img]][🧮kloc]                                                                                                                                                                                                                                                               |
| Documentation           | [![Current release on RubyDoc.info][📜docs-cr-rd-img]][🚎yard-current] [![YARD on Galtzo.com][📜docs-head-rd-img]][🚎yard-head] [![Maintainer Blog][🚂maint-blog-img]][🚂maint-blog] [![GitHub Wiki][📜gh-wiki-img]][📜gh-wiki]                                                                                                                                     |
| Compliance              | [![License: MIT][📄license-img]][📄license-ref] [![Compatible with Apache Software Projects: Verified by SkyWalking Eyes][📄license-compat-img]][📄license-compat] [![📄ilo-declaration-img]][📄ilo-declaration] [![Security Policy][🔐security-img]][🔐security] [![Contributor Covenant 2.1][🪇conduct-img]][🪇conduct] [![SemVer 2.0.0][📌semver-img]][📌semver] |
| Style                   | [![Enforced Code Style Linter][💎rlts-img]][💎rlts] [![Keep-A-Changelog 1.0.0][📗keep-changelog-img]][📗keep-changelog] [![Gitmoji Commits][📌gitmoji-img]][📌gitmoji] [![Compatibility appraised by: appraisal2][💎appraisal2-img]][💎appraisal2]                                                                                                                  |
| Maintainer 🎖️          | [![Follow Me on LinkedIn][💖🖇linkedin-img]][💖🖇linkedin] [![Follow Me on Ruby.Social][💖🐘ruby-mast-img]][💖🐘ruby-mast] [![Follow Me on Bluesky][💖🦋bluesky-img]][💖🦋bluesky] [![Contact Maintainer][🚂maint-contact-img]][🚂maint-contact] [![My technical writing][💖💁🏼‍♂️devto-img]][💖💁🏼‍♂️devto]                                                      |
| `...` 💖                | [![Find Me on WellFound:][💖✌️wellfound-img]][💖✌️wellfound] [![Find Me on CrunchBase][💖💲crunchbase-img]][💖💲crunchbase] [![My LinkTree][💖🌳linktree-img]][💖🌳linktree] [![More About Me][💖💁🏼‍♂️aboutme-img]][💖💁🏼‍♂️aboutme] [🧊][💖🧊berg] [🐙][💖🐙hub]  [🛖][💖🛖hut] [🧪][💖🧪lab]                                                                   |

### Compatibility

Compatible with MRI Ruby 2.0+, and concordant releases of JRuby, and TruffleRuby.

| 🚚 _Amazing_ test matrix was brought to you by | 🔎 appraisal2 🔎 and the color 💚 green 💚             |
|------------------------------------------------|--------------------------------------------------------|
| 👟 Check it out!                               | ✨ [github.com/appraisal-rb/appraisal2][💎appraisal2] ✨ |

### Enterprise Support [![Tidelift](https://tidelift.com/badges/package/rubygems/omniauth-ldap)](https://tidelift.com/subscription/pkg/rubygems-omniauth-ldap?utm_source=rubygems-omniauth-ldap&utm_medium=referral&utm_campaign=readme)

Available as part of the Tidelift Subscription.

<details markdown="1">
  <summary>Need enterprise-level guarantees?</summary>

The maintainers of this and thousands of other packages are working with Tidelift to deliver commercial support and maintenance for the open source packages you use to build your applications. Save time, reduce risk, and improve code health, while paying the maintainers of the exact packages you use.

[![Get help from me on Tidelift][🏙️entsup-tidelift-img]][🏙️entsup-tidelift]

- 💡Subscribe for support guarantees covering _all_ your FLOSS dependencies
- 💡Tidelift is part of [Sonar][🏙️entsup-tidelift-sonar]
- 💡Tidelift pays maintainers to maintain the software you depend on!<br/>📊`@`Pointy Haired Boss: An [enterprise support][🏙️entsup-tidelift] subscription is "[never gonna let you down][🧮kloc]", and *supports* open source maintainers

Alternatively:

- [![Live Chat on Discord][✉️discord-invite-img-ftb]][✉️discord-invite]
- [![Get help from me on Upwork][👨🏼‍🏫expsup-upwork-img]][👨🏼‍🏫expsup-upwork]
- [![Get help from me on Codementor][👨🏼‍🏫expsup-codementor-img]][👨🏼‍🏫expsup-codementor]

</details>

## ✨ Installation

Install the gem and add to the application's Gemfile by executing:

```console
bundle add omniauth-ldap
```

If bundler is not being used to manage dependencies, install the gem by executing:

```console
gem install omniauth-ldap
```

### 🔒 Secure Installation

<details markdown="1">
  <summary>For Medium or High Security Installations</summary>

This gem is cryptographically signed, and has verifiable [SHA-256 and SHA-512][💎SHA_checksums] checksums by
[stone_checksums][💎stone_checksums]. Be sure the gem you install hasn’t been tampered with
by following the instructions below.

Add my public key (if you haven’t already, expires 2045-04-29) as a trusted certificate:

```console
gem cert --add <(curl -Ls https://raw.github.com/galtzo-floss/certs/main/pboling.pem)
```

You only need to do that once.  Then proceed to install with:

```console
gem install omniauth-ldap -P HighSecurity
```

The `HighSecurity` trust profile will verify signed gems, and not allow the installation of unsigned dependencies.

If you want to up your security game full-time:

```console
bundle config set --global trust-policy MediumSecurity
```

`MediumSecurity` instead of `HighSecurity` is necessary if not all the gems you use are signed.

NOTE: Be prepared to track down certs for signed gems and add them the same way you added mine.

</details>

## ⚙️ Configuration

The following options are available for configuring the OmniAuth LDAP strategy:

### Required Options

- `:host` - The hostname or IP address of the LDAP server.
- `:base` - The base DN for the LDAP search.
- `:uid` or `:filter` - Either `:uid` (the LDAP attribute for username, default: "sAMAccountName") or `:filter` (LDAP filter for searching user entries). If `:filter` is provided, `:uid` is not required. Note: This `:uid` option is the search attribute, not the top-level `auth.uid` in the OmniAuth result.

### Optional Options

- `:title` - The title for the authentication form (default: "LDAP Authentication").
- `:port` - The port number of the LDAP server (default: 389).
- `:encryption` - The connection method. Allowed values: `:plain`, `:ssl`, `:tls` (default: `:plain`). `:method` is still accepted for compatibility, but is deprecated.
- `:bind_dn` - The DN to bind with for searching users (required if anonymous access is not allowed).
- `:password` - The password for the bind DN.
- `:name_proc` - A proc to process the username before using it in the search (default: identity proc that returns the username unchanged).
- `:try_sasl` - Whether to use SASL authentication (default: false).
- `:sasl_mechanisms` - Array of SASL mechanisms to use (e.g., ["DIGEST-MD5", "GSS-SPNEGO"]).
- `:allow_anonymous` - Whether to allow anonymous binding (default: false).
- `:logger` - A logger instance for debugging (optional, for internal use).
- `:password_policy` - When true, the strategy will request the LDAP Password Policy response control (OID `1.3.6.1.4.1.42.2.27.8.5.1`) during the user bind. If the server supports it, the adaptor exposes:
  - `adaptor.last_operation_result` — the last Net::LDAP operation result object.
  - `adaptor.last_password_policy_response` — the matching password policy response control (implementation-specific object). This can indicate conditions such as password expired, account locked, reset required, or grace logins remaining (per the draft RFC).
- `:connect_timeout` - Maximum time in seconds to wait when establishing the TCP connection to the LDAP server. Forwarded to `Net::LDAP`.
- `:read_timeout` - Maximum time in seconds to wait for reads during LDAP operations (search/bind). Forwarded to `Net::LDAP`.
- `:mapping` - Customize how LDAP attributes map to the returned `auth.info` hash. A sensible default mapping is built into the strategy and will be merged with your overrides. See `lib/omniauth/strategies/ldap.rb` for the default keys and behavior; values can be a String (single attribute), an Array (first present attribute wins), or a Hash (string pattern with placeholders like `%0` combined from multiple attributes).
- `:header_auth` - Enable trusted upstream identity SSO (default: false). When enabled, the strategy trusts the configured header/env key, performs an LDAP lookup, and skips the user password bind.
- `:header_name` - Header/env key used for trusted header SSO (default: "REMOTE_USER").
- `:header_auth_source` - Trusted identity source for header SSO (default: `:env`). Use `:env` to read only `env["REMOTE_USER"]`-style server variables. Use `:http_header` to read only Rack `HTTP_` header keys such as `env["HTTP_REMOTE_USER"]`; only configure this behind a proxy that strips client-supplied copies.
- `:header_auth_require_tls` - Require TLS for trusted header SSO requests (default: true).

Example enabling password policy:

```ruby
use OmniAuth::Builder do
  provider :ldap,
    host: "ldap.example.com",
    base: "dc=example,dc=com",
    uid: "uid",
    bind_dn: "cn=search,dc=example,dc=com",
    password: ENV["LDAP_SEARCH_PASSWORD"],
    password_policy: true
end
```

Note: This is best-effort and compatible with a range of net-ldap versions. If your server supports the control, you can inspect the response via the `adaptor` instance during/after authentication (for example in a failure handler) to tailor error messages.

### Auth Hash UID vs LDAP :uid (search attribute)

- By design, the top-level `auth.uid` returned by this strategy is the entry's Distinguished Name (DN).
- The configuration option `:uid` controls which LDAP attribute is used to locate the entry (or to build the filter), not the value exposed as `auth.uid`.
- Your LDAP "account name" (for example, `sAMAccountName` on Active Directory or `uid` on many schemas) is exposed via `auth.info.nickname` and is also available in `auth.extra.raw_info`.

Why DN for `auth.uid`?

- DN is the canonical, globally unique identifier for an LDAP entry and is always present in search results. See LDAPv3 and DN syntax: [RFC 4511][rfc4511] (LDAP protocol) and [RFC 4514][rfc4514] (String Representation of Distinguished Names).
- Attributes like `uid` (defined in [RFC 4519][rfc4519]) or `sAMAccountName` (Active Directory–specific) may be absent, duplicated across parts of the DIT, or vary between directories. Using DN ensures consistent behavior across AD, OpenLDAP, and other servers.
- This trade-off favors cross-directory interoperability and stability for apps that need a unique identifier.

Where to find the "username"-style value

- `auth.info.nickname` maps from the first present of: `uid`, `userid`, or `sAMAccountName`.
- You can also read the raw attribute from `auth.extra.raw_info` (a `Net::LDAP::Entry`):

```ruby
post "/auth/ldap/callback" do
  auth = request.env["omniauth.auth"]
  dn = auth.uid                                # => "cn=alice,ou=users,dc=example,dc=com"
  username = auth.info.nickname                # => "alice" (from uid/sAMAccountName)
  # Or, directly from raw_info (case-insensitive keys):
  sams = auth.extra.raw_info[:samaccountname]
  sam = sams.first if sams
  # ...
end
```

If you need top-level `auth.uid` to be something other than the DN (for example, `sAMAccountName`), you'll currently need to read it from `auth.info.nickname` (or `raw_info`) in your app. Changing the top-level `uid` mapping would be a breaking behavior change for existing users; if you have a use-case, please open an issue to discuss a configurable mapping.

## 🔧 Basic Usage

The strategy exposes a simple Rack middleware and can be used in plain Rack apps, Sinatra, or Rails.
With OmniAuth 2.x, initiate authentication with `POST /auth/ldap`; `GET /auth/ldap` returns 404 by default. Older OmniAuth 1.x deployments may still render the form on `GET /auth/ldap`. Handle the callback at `/auth/ldap/callback`.

Below are several concrete examples to get you started.

### Minimal Rack setup

```ruby
# config.ru
require "rack"
require "omniauth-ldap"

use Rack::Session::Cookie, secret: "change_me"
use OmniAuth::Builder do
  provider :ldap,
    host: "ldap.example.com",
    port: 389,
    encryption: :plain,
    base: "dc=example,dc=com",
    uid: "uid",
    title: "Example LDAP"
end

run lambda { |env| [404, {"Content-Type" => "text/plain"}, [env.key?("omniauth.auth").to_s]] }
```

Submit `POST /auth/ldap` to initiate authentication. With OmniAuth 2.x, the middleware renders the login form on POST when credentials are not already present; with OmniAuth 1.x, `GET /auth/ldap` can also render the form.

### Sinatra example

```ruby
require "sinatra"
require "omniauth-ldap"

use Rack::Session::Cookie, secret: "change_me"
use OmniAuth::Builder do
  provider :ldap,
    title: "Company LDAP",
    host: "ldap.company.internal",
    base: "dc=company,dc=local",
    uid: "sAMAccountName",
    name_proc: proc { |username| username.gsub(/@.*$/, "") }
end

get "/" do
  '<form action="/auth/ldap" method="post"><button type="submit">Sign in with LDAP</button></form>'
end

post "/auth/ldap/callback" do
  auth = request.env["omniauth.auth"]
  "Hello, #{auth.info["name"]}"
end
```

### Rails (initializer) example

Create `config/initializers/omniauth.rb`:

```ruby
Rails.application.config.middleware.use(OmniAuth::Builder) do
  provider :ldap,
    title: "Acme LDAP",
    host: "ldap.acme.internal",
    port: 389,
    base: "dc=acme,dc=corp",
    uid: "uid",
    bind_dn: "cn=search,dc=acme,dc=corp",
    password: ENV["LDAP_SEARCH_PASSWORD"],
    name_proc: proc { |n| n.split("@").first }
end
```

Then submit users to `/auth/ldap` with POST in your app (for example, from a Devise sign-in page).

### Use JSON Body

This gem is compatible with JSON-encoded POST bodies as well as traditional form-encoded.

- Set header `Content-Type` to `application/json`.
- Send a JSON object containing `username` and `password`.
- Rails automatically exposes parsed JSON params via `env["action_dispatch.request.request_parameters"]`, which this strategy reads first. In non-Rails Rack apps, ensure you use a JSON parser middleware if you post raw JSON.

Examples

- curl (JSON):

  ```bash
  curl -i \
    -X POST \
    -H 'Content-Type: application/json' \
    -d '{"username":"alice","password":"secret"}' \
    http://localhost:3000/auth/ldap
  ```

  The request phase will redirect to `/auth/ldap/callback` when both fields are present.

- curl (form-encoded, still supported):

  ```bash
  curl -i \
    -X POST \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'username=alice' \
    --data-urlencode 'password=secret' \
    http://localhost:3000/auth/ldap
  ```

- Browser (JavaScript fetch):

  ```js
  fetch('/auth/ldap', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'alice', password: 'secret' })
  }).then(res => {
    if (res.redirected) {
      window.location = res.url; // typically /auth/ldap/callback
    }
  });
  ```

Notes

- You can still initiate authentication with a regular form POST and then submit credentials as form-encoded data. JSON is an additional option, not a replacement.
- In the callback phase (`POST /auth/ldap/callback`), the strategy reads JSON credentials the same way; Rails exposes them via `action_dispatch.request.request_parameters` and non-Rails apps should use a JSON parser middleware.

### Using a custom filter

If you need to restrict authentication to a group or use a more complex lookup, pass `:filter`. Use `%{username}` — it will be replaced with the processed username (after `:name_proc`).

```ruby
provider :ldap,
  host: "ldap.example.com",
  base: "dc=example,dc=com",
  filter: "(&(uid=%{username})(memberOf=cn=myapp-users,ou=groups,dc=example,dc=com))",
  bind_dn: "cn=search,dc=example,dc=com",
  password: ENV["LDAP_SEARCH_PASSWORD"]
```

What `:filter` actually does

- If `:filter` is provided, the strategy constructs an LDAP filter string by substituting `%{username}` with the submitted username after applying `:name_proc`, escaping special characters per RFC 4515, and passes it to the directory search.
- In the normal password flow, a successful search returns the user's DN and we then bind as that DN with the submitted password.
- In trusted header SSO flow (`header_auth: true`), we only perform the search and skip the user password bind; if the search returns no entry, authentication fails.
- If `:filter` is not provided, the strategy falls back to a simple equality filter using `:uid` (e.g. `(uid=alice)`).

Notes on escaping and safety

- We escape the interpolated username with `Net::LDAP::Filter.escape`, which protects against LDAP injection and handles special characters like `(`, `)`, `*`, and `\`.
- Your static filter text is used as-is — keep it to a valid LDAP filter expression and only use `%{username}` for substitution.

Group-based recipes

- Active Directory (simple group):

  ```text
  (&(sAMAccountName=%{username})(memberOf=cn=myapp-users,ou=groups,dc=example,dc=com))
  ```

- Active Directory (nested groups via matchingRuleInChain):

  ```text
  (&(sAMAccountName=%{username})(memberOf:1.2.840.113556.1.4.1941:=cn=myapp-users,ou=groups,dc=example,dc=com))
  ```

- OpenLDAP (groupOfNames):

  ```text
  (&(uid=%{username})(memberOf=cn=myapp-users,ou=groups,dc=example,dc=com))
  ```

  or, if you can't use `memberOf` overlays, filter on the group and member DN:

  ```text
  (&(uid=%{username})(|(uniqueMember=uid=%{username},ou=people,dc=example,dc=com)(member=uid=%{username},ou=people,dc=example,dc=com)))
  ```

Username normalization examples

- If your users sign in with an email but the directory expects a short name, combine `:name_proc` with `:filter`:

  ```ruby
  provider :ldap,
    name_proc: proc { |n| n.split("@").first },
    filter: "(&(sAMAccountName=%{username})(memberOf=cn=myapp-users,ou=groups,dc=example,dc=com))"
    # other settings...
  ```

Discourse plugin (jonmbake/discourse-ldap-auth)

- That plugin forwards its `filter` setting to this gem. You can therefore paste the same filter strings shown above.
- Example (allow only members of `forum-users`):

  ```text
  (&(uid=%{username})(memberOf=cn=forum-users,ou=groups,dc=example,dc=com))
  ```

- If users type an email address but your directory matches on a short user id, also configure `name_proc` accordingly in your app (or the plugin, if supported).

### SASL (advanced)

SASL enables alternative bind mechanisms. Only enable if you understand the server-side requirements.

```ruby
provider :ldap,
  host: "ldap.example.com",
  base: "dc=example,dc=com",
  try_sasl: true,
  sasl_mechanisms: ["DIGEST-MD5"],
  uid: "uid"
```

Supported mechanisms include "DIGEST-MD5" and "GSS-SPNEGO" depending on your environment and gems.

### Name processing and examples

If users log in with an email but LDAP expects a short username, use `:name_proc` to normalize the submitted value:

```ruby
provider :ldap,
  host: "ldap.example.com",
  base: "dc=example,dc=com",
  uid: "sAMAccountName",
  name_proc: proc { |name| name.gsub(/@.*$/, "") }
```

This trims `alice@example.com` to `alice` before searching.

### Mounted under a subdirectory (SCRIPT_NAME)

If your app is served from a path prefix (for example, behind a reverse proxy at `/myapp`, or mounted via Rack::URLMap, or Rails `relative_url_root`), the OmniAuth callback must include that subdirectory. This strategy uses `callback_url` for the form action and redirects, so it automatically includes any `SCRIPT_NAME` set by Rack/Rails. In other words, you typically do not need any special configuration beyond ensuring `SCRIPT_NAME` is correct in the request environment.

- Works out-of-the-box when:
  - You mount the app at a path using Rack’s `map`/`URLMap`.
  - You set Rails’ `config.relative_url_root` (or `RAILS_RELATIVE_URL_ROOT`) or deploy under a prefix with a reverse proxy that sets `SCRIPT_NAME`.

Rack example (mounted at /myapp):

```ruby
# config.ru
require "rack"
require "omniauth-ldap"

app = Rack::Builder.new do
  use(Rack::Session::Cookie, secret: "change_me")
  use(OmniAuth::Builder) do
    provider(
      :ldap,
      host: "ldap.example.com",
      base: "dc=example,dc=com",
      uid: "uid",
      title: "Example LDAP",
    )
  end

  run(->(env) { [404, {"Content-Type" => "text/plain"}, [env.key?("omniauth.auth").to_s]] })
end

run Rack::URLMap.new(
  "/myapp" => app,
)
```

- Visiting `POST /myapp/auth/ldap` renders the login form with `action='http://host/myapp/auth/ldap/callback'`.
- Any redirects (including header-based SSO fast path) will also point to `http://host/myapp/auth/ldap/callback`.

Rails example (relative_url_root):

```ruby
# config/environments/production.rb (or an initializer)
Rails.application.configure do
  config.relative_url_root = "/myapp"  # or set ENV["RAILS_RELATIVE_URL_ROOT"]
end

# config/initializers/omniauth.rb
Rails.application.config.middleware.use(OmniAuth::Builder) do
  provider :ldap,
    title: "Acme LDAP",
    host: "ldap.acme.internal",
    base: "dc=acme,dc=corp",
    uid: "uid",
    bind_dn: "cn=search,dc=acme,dc=corp",
    password: ENV["LDAP_SEARCH_PASSWORD"],
    name_proc: proc { |n| n.split("@").first }
end
```

- With `relative_url_root` set, Rails/Rack provide `SCRIPT_NAME=/myapp`, and this strategy will issue a form with `action='.../myapp/auth/ldap/callback'` and redirect accordingly.

Behind proxies with unusual host/proto handling (optional):

OmniAuth usually derives the correct scheme/host/prefix from Rack (and standard `X-Forwarded-*` headers). If your environment produces incorrect absolute URLs, you can override the computed host and prefix by setting `OmniAuth.config.full_host`:

```ruby
OmniAuth.config.full_host = lambda do |env|
  scheme = (env["HTTP_X_FORWARDED_PROTO"] || env["rack.url_scheme"]).to_s.split(",").first
  host = env["HTTP_X_FORWARDED_HOST"] || env["HTTP_HOST"] || [env["SERVER_NAME"], env["SERVER_PORT"]].compact.join(":")
  script = env["SCRIPT_NAME"].to_s
  "#{scheme}://#{host}#{script}"
end
```

Note: You generally do not need this override. Prefer configuring your proxy to pass standard `X-Forwarded-Proto` and `X-Forwarded-Host` headers and let Rack/OmniAuth compute the full URL.

- Header-based SSO (`header_auth: true`) also respects `SCRIPT_NAME`; when a trusted header is present on `POST /myapp/auth/ldap`, the strategy redirects to `http://host/myapp/auth/ldap/callback`.

### Trusted header SSO (REMOTE_USER and friends)

Some deployments terminate SSO at a reverse proxy or portal and forward the already-authenticated user identity via a server-set environment variable or HTTP header such as `REMOTE_USER`.
When you enable this mode, the LDAP strategy will trust the upstream header, perform a directory lookup for that user, and complete OmniAuth without asking the user for a password.

Important: Only enable this behind a trusted front-end that authenticates users before they can reach the OmniAuth endpoint. When `header_auth` is enabled the strategy logs a prominent security warning because it trusts the upstream identity completely.

Configuration options:

- `:header_auth` (Boolean, default: false) — Enable trusted header SSO.
- `:header_name` (String, default: "REMOTE_USER") — The env/header key to read.
- `:header_auth_source` (`:env` or `:http_header`, default: `:env`) — Which Rack env key form to trust.
  - `:env` reads only the exact server-set environment key, such as `env["REMOTE_USER"]`.
  - `:http_header` reads only the Rack HTTP header key, such as `env["HTTP_REMOTE_USER"]`. Only use this behind a proxy that strips client-sent copies of the header before setting its trusted value.
- `:header_auth_require_tls` (Boolean, default: true) — Raise an error if trusted header SSO is used on a non-TLS request.
- `:name_proc` is applied to the header value before search (e.g., to strip a domain part).
- Search is done using your configured `:uid` or `:filter` and the service bind (`:bind_dn`/`:password`) or anonymous bind if allowed.

Minimal Rack example:

```ruby
use OmniAuth::Builder do
  provider :ldap,
    host: "ldap.example.com",
    base: "dc=example,dc=com",
    uid: "uid",
    bind_dn: "cn=search,dc=example,dc=com",
    password: ENV["LDAP_SEARCH_PASSWORD"],
    header_auth: true,                  # trust the configured upstream identity
    header_name: "REMOTE_USER",        # default
    header_auth_source: :env,           # default; reads env["REMOTE_USER"]
    name_proc: proc { |n| n.split("@").first }
end
```

Rails initializer example:

```ruby
Rails.application.config.middleware.use(OmniAuth::Builder) do
  provider :ldap,
    title: "Acme LDAP",
    host: "ldap.acme.internal",
    base: "dc=acme,dc=corp",
    uid: "sAMAccountName",
    bind_dn: "cn=search,dc=acme,dc=corp",
    password: ENV["LDAP_SEARCH_PASSWORD"],
    header_auth: true,
    header_name: "REMOTE_USER",
    header_auth_source: :env,
    # Optionally restrict with a group filter while using the header value
    filter: "(&(sAMAccountName=%{username})(memberOf=cn=myapp-users,ou=groups,dc=acme,dc=corp))",
    name_proc: proc { |n| n.gsub(/@.*$/, "") }
end
```

Flow:

- If `header_auth` is on and the header is present when the request hits `/auth/ldap`, the strategy immediately redirects to `/auth/ldap/callback`.
- In the callback, the strategy searches the directory for that user and maps their attributes; no user password bind is attempted.
- If the header is missing (or `header_auth` is false), the normal username/password form flow is used.

Security checklist:

- Prefer `header_auth_source: :env` for server-set variables such as `REMOTE_USER`.
- Use `header_auth_source: :http_header` only when your reverse proxy strips user-controlled copies of the header and sets the canonical value itself.
- Keep `header_auth_require_tls` enabled unless a separate trusted channel protects traffic between the proxy and your app.
- Consider also restricting with a group-based `:filter` so only authorized users can sign in.

## 🦷 FLOSS Funding

While omniauth tools are free software and will always be, the project would benefit immensely from some funding.
Raising a monthly budget of... "dollars" would make the project more sustainable.

We welcome both individual and corporate sponsors! We also offer a
wide array of funding channels to account for your preferences.
Currently, [GitHub Sponsors][🖇sponsor], and [Liberapay][⛳liberapay] are our preferred funding platforms.

**If you're working in a company that's making significant use of omniauth tools we'd
appreciate it if you suggest to your company to become a omniauth sponsor.**

You can support the development of omniauth tools via
[GitHub Sponsors][🖇sponsor],
[Liberapay][⛳liberapay],
[PayPal][🖇paypal],
and [Tidelift][🏙️entsup-tidelift].

| 📍 NOTE                                                                                                                                                                                                              |
|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| If doing a sponsorship in the form of donation is problematic for your company <br/> from an accounting standpoint, we'd recommend the use of Tidelift, <br/> where you can get a support-like subscription instead. |

### Another way to support open-source

I’m driven by a passion to foster a thriving open-source community – a space where people can tackle complex problems, no matter how small.  Revitalizing libraries that have fallen into disrepair, and building new libraries focused on solving real-world challenges, are my passions.  I was recently affected by layoffs, and the tech jobs market is unwelcoming. I’m reaching out here because your support would significantly aid my efforts to provide for my family, and my farm (11 🐔 chickens, 2 🐶 dogs, 3 🐰 rabbits, 8 🐈‍ cats).

If you work at a company that uses my work, please encourage them to support me as a corporate sponsor. My work on gems you use might show up in `bundle fund`.

I’m developing a new library, [floss_funding][🖇floss-funding-gem], designed to empower open-source developers like myself to get paid for the work we do, in a sustainable way. Please give it a look.

**[Floss-Funding.dev][🖇floss-funding.dev]: 👉️ No network calls. 👉️ No tracking. 👉️ No oversight. 👉️ Minimal crypto hashing. 💡 Easily disabled nags**

[![Sponsor Me on Github][🖇sponsor-img]][🖇sponsor] [![Liberapay Goal Progress][⛳liberapay-img]][⛳liberapay] [![Donate on PayPal][🖇paypal-img]][🖇paypal] [![Buy me a coffee][🖇buyme-small-img]][🖇buyme] [![Donate on Polar][🖇polar-img]][🖇polar] [![Donate to my FLOSS efforts at ko-fi.com][🖇kofi-img]][🖇kofi] [![Donate to my FLOSS efforts using Patreon][🖇patreon-img]][🖇patreon]

## 🔐 Security

See [SECURITY.md][🔐security].

## 🤝 Contributing

If you need some ideas of where to help, you could work on adding more code coverage,
or if it is already 💯 (see [below](#code-coverage)) check [reek](REEK), [issues][🤝gh-issues], or [PRs][🤝gh-pulls],
or use the gem and think about how it could be better.

We [![Keep A Changelog][📗keep-changelog-img]][📗keep-changelog] so if you make changes, remember to update it.

See [CONTRIBUTING.md][🤝contributing] for more detailed instructions.

### 🚀 Release Instructions

See [CONTRIBUTING.md][🤝contributing].

### Code Coverage

[![Coverage Graph][🏀codecov-g]][🏀codecov]

[![Coveralls Test Coverage][🏀coveralls-img]][🏀coveralls]

### 🪇 Code of Conduct

Everyone interacting with this project's codebases, issue trackers,
chat rooms and mailing lists agrees to follow the [![Contributor Covenant 2.1][🪇conduct-img]][🪇conduct].

## 🌈 Contributors

[![Contributors][🖐contributors-img]][🖐contributors]

Made with [contributors-img][🖐contrib-rocks].

<details>
    <summary>⭐️ Star History</summary>

<a href="https://star-history.com/#omniauth/omniauth-ldap&Date">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=omniauth/omniauth-ldap&type=Date&theme=dark" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=omniauth/omniauth-ldap&type=Date" />
   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=omniauth/omniauth-ldap&type=Date" />
 </picture>
</a>

</details>

## 📌 Versioning

This Library adheres to [![Semantic Versioning 2.0.0][📌semver-img]][📌semver].
Violations of this scheme should be reported as bugs.
Specifically, if a minor or patch version is released that breaks backward compatibility,
a new version should be immediately released that restores compatibility.
Breaking changes to the public API will only be introduced with new major versions.

> dropping support for a platform is both obviously and objectively a breaking change <br/>
>—Jordan Harband ([@ljharb](https://github.com/ljharb), maintainer of SemVer) [in SemVer issue 716][📌semver-breaking]

I understand that policy doesn't work universally ("exceptions to every rule!"),
but it is the policy here.
As such, in many cases it is good to specify a dependency on this library using
the [Pessimistic Version Constraint][📌pvc] with two digits of precision.

For example:

```ruby
spec.add_dependency("omniauth-ldap", "~> 1.0")
```

<details markdown="1">
<summary>📌 Is "Platform Support" part of the public API? More details inside.</summary>

SemVer should, IMO, but doesn't explicitly, say that dropping support for specific Platforms
is a *breaking change* to an API, and for that reason the bike shedding is endless.

To get a better understanding of how SemVer is intended to work over a project's lifetime,
read this article from the creator of SemVer:

- ["Major Version Numbers are Not Sacred"][📌major-versions-not-sacred]

</details>

See [CHANGELOG.md][📌changelog] for a list of releases.

## 📄 License

The gem is available as open source under the terms of
the [MIT License][📄license] [![License: MIT][📄license-img]][📄license-ref].
See [LICENSE.txt][📄license] for the official [Copyright Notice][📄copyright-notice-explainer].

### © Copyright

<ul>
    <li>
        Copyright (c) 2025 - 2026 Peter H. Boling, of
        <a href="https://discord.gg/3qme4XHNKN">
            Galtzo.com
            <picture>
              <img src="https://logos.galtzo.com/assets/images/galtzo-floss/avatar-128px-blank.svg" alt="Galtzo.com Logo (Wordless) by Aboling0, CC BY-SA 4.0" width="24">
            </picture>
        </a>, and omniauth-ldap contributors.
    </li>
    <li>
        Copyright (c) 2014 David Benko
    </li>
    <li>
        Copyright (c) 2011 by Ping Yu and Intridea, Inc.
    </li>
</ul>

## 🤑 A request for help

Maintainers have teeth and need to pay their dentists.
After getting laid off in an RIF in March, and encountering difficulty finding a new one,
I began spending most of my time building open source tools.
I'm hoping to be able to pay for my kids' health insurance this month,
so if you value the work I am doing, I need your support.
Please consider sponsoring me or the project.

To join the community or get help 👇️ Join the Discord.

[![Live Chat on Discord][✉️discord-invite-img-ftb]][✉️discord-invite]

To say "thanks!" ☝️ Join the Discord or 👇️ send money.

[![Sponsor me on GitHub Sponsors][🖇sponsor-bottom-img]][🖇sponsor] 💌 [![Sponsor me on Liberapay][⛳liberapay-bottom-img]][⛳liberapay] 💌 [![Donate on PayPal][🖇paypal-bottom-img]][🖇paypal]

### Please give the project a star ⭐ ♥.

Thanks for RTFM. ☺️

[⛳liberapay-img]: https://img.shields.io/liberapay/goal/pboling.svg?logo=liberapay&color=a51611&style=flat
[⛳liberapay-bottom-img]: https://img.shields.io/liberapay/goal/pboling.svg?style=for-the-badge&logo=liberapay&color=a51611
[⛳liberapay]: https://liberapay.com/pboling/donate
[🖇sponsor-img]: https://img.shields.io/badge/Sponsor_Me!-pboling.svg?style=social&logo=github
[🖇sponsor-bottom-img]: https://img.shields.io/badge/Sponsor_Me!-pboling-blue?style=for-the-badge&logo=github
[🖇sponsor]: https://github.com/sponsors/pboling
[🖇polar-img]: https://img.shields.io/badge/polar-donate-a51611.svg?style=flat
[🖇polar]: https://polar.sh/pboling
[🖇kofi-img]: https://img.shields.io/badge/ko--fi-%E2%9C%93-a51611.svg?style=flat
[🖇kofi]: https://ko-fi.com/O5O86SNP4
[🖇patreon-img]: https://img.shields.io/badge/patreon-donate-a51611.svg?style=flat
[🖇patreon]: https://patreon.com/galtzo
[🖇buyme-small-img]: https://img.shields.io/badge/buy_me_a_coffee-%E2%9C%93-a51611.svg?style=flat
[🖇buyme-img]: https://img.buymeacoffee.com/button-api/?text=Buy%20me%20a%20latte&emoji=&slug=pboling&button_colour=FFDD00&font_colour=000000&font_family=Cookie&outline_colour=000000&coffee_colour=ffffff
[🖇buyme]: https://www.buymeacoffee.com/pboling
[🖇paypal-img]: https://img.shields.io/badge/donate-paypal-a51611.svg?style=flat&logo=paypal
[🖇paypal-bottom-img]: https://img.shields.io/badge/donate-paypal-a51611.svg?style=for-the-badge&logo=paypal&color=0A0A0A
[🖇paypal]: https://www.paypal.com/paypalme/peterboling
[🖇floss-funding.dev]: https://floss-funding.dev
[🖇floss-funding-gem]: https://github.com/galtzo-floss/floss_funding
[✉️discord-invite]: https://discord.gg/3qme4XHNKN
[✉️discord-invite-img-ftb]: https://img.shields.io/discord/1373797679469170758?style=for-the-badge&logo=discord
[✉️ruby-friends-img]: https://img.shields.io/badge/daily.dev-%F0%9F%92%8E_Ruby_Friends-0A0A0A?style=for-the-badge&logo=dailydotdev&logoColor=white
[✉️ruby-friends]: https://app.daily.dev/squads/rubyfriends

[✇bundle-group-pattern]: https://gist.github.com/pboling/4564780
[⛳️gem-namespace]: https://github.com/omniauth/omniauth-ldap
[⛳️namespace-img]: https://img.shields.io/badge/namespace-Omniauth::Ldap-3C2D2D.svg?style=square&logo=ruby&logoColor=white
[⛳️gem-name]: https://bestgems.org/gems/omniauth-ldap
[⛳️name-img]: https://img.shields.io/badge/name-omniauth--ldap-3C2D2D.svg?style=square&logo=rubygems&logoColor=red
[⛳️tag-img]: https://img.shields.io/github/tag/omniauth/omniauth-ldap.svg
[⛳️tag]: http://github.com/omniauth/omniauth-ldap/releases
[🚂maint-blog]: http://www.railsbling.com/tags/omniauth-ldap
[🚂maint-blog-img]: https://img.shields.io/badge/blog-railsbling-0093D0.svg?style=for-the-badge&logo=rubyonrails&logoColor=orange
[🚂maint-contact]: http://www.railsbling.com/contact
[🚂maint-contact-img]: https://img.shields.io/badge/Contact-Maintainer-0093D0.svg?style=flat&logo=rubyonrails&logoColor=red
[💖🖇linkedin]: http://www.linkedin.com/in/peterboling
[💖🖇linkedin-img]: https://img.shields.io/badge/PeterBoling-LinkedIn-0B66C2?style=flat&logo=newjapanprowrestling
[💖✌️wellfound]: https://wellfound.com/u/peter-boling
[💖✌️wellfound-img]: https://img.shields.io/badge/peter--boling-orange?style=flat&logo=wellfound
[💖💲crunchbase]: https://www.crunchbase.com/person/peter-boling
[💖💲crunchbase-img]: https://img.shields.io/badge/peter--boling-purple?style=flat&logo=crunchbase
[💖🐘ruby-mast]: https://ruby.social/@galtzo
[💖🐘ruby-mast-img]: https://img.shields.io/mastodon/follow/109447111526622197?domain=https://ruby.social&style=flat&logo=mastodon&label=Ruby%20@galtzo
[💖🦋bluesky]: https://bsky.app/profile/galtzo.com
[💖🦋bluesky-img]: https://img.shields.io/badge/@galtzo.com-0285FF?style=flat&logo=bluesky&logoColor=white
[💖🌳linktree]: https://linktr.ee/galtzo
[💖🌳linktree-img]: https://img.shields.io/badge/galtzo-purple?style=flat&logo=linktree
[💖💁🏼‍♂️devto]: https://dev.to/galtzo
[💖💁🏼‍♂️devto-img]: https://img.shields.io/badge/dev.to-0A0A0A?style=flat&logo=devdotto&logoColor=white
[💖💁🏼‍♂️aboutme]: https://about.me/peter.boling
[💖💁🏼‍♂️aboutme-img]: https://img.shields.io/badge/about.me-0A0A0A?style=flat&logo=aboutme&logoColor=white
[💖🧊berg]: https://codeberg.org/pboling
[💖🐙hub]: https://github.org/pboling
[💖🛖hut]: https://sr.ht/~galtzo/
[💖🧪lab]: https://gitlab.com/pboling
[👨🏼‍🏫expsup-upwork]: https://www.upwork.com/freelancers/~014942e9b056abdf86?mp_source=share
[👨🏼‍🏫expsup-upwork-img]: https://img.shields.io/badge/UpWork-13544E?style=for-the-badge&logo=Upwork&logoColor=white
[👨🏼‍🏫expsup-codementor]: https://www.codementor.io/peterboling?utm_source=github&utm_medium=button&utm_term=peterboling&utm_campaign=github
[👨🏼‍🏫expsup-codementor-img]: https://img.shields.io/badge/CodeMentor-Get_Help-1abc9c?style=for-the-badge&logo=CodeMentor&logoColor=white
[🏙️entsup-tidelift]: https://tidelift.com/subscription/pkg/rubygems-omniauth-ldap?utm_source=rubygems-omniauth-ldap&utm_medium=referral&utm_campaign=readme
[🏙️entsup-tidelift-img]: https://img.shields.io/badge/Tidelift_and_Sonar-Enterprise_Support-FD3456?style=for-the-badge&logo=sonar&logoColor=white
[🏙️entsup-tidelift-sonar]: https://blog.tidelift.com/tidelift-joins-sonar
[💁🏼‍♂️peterboling]: http://www.peterboling.com
[🚂railsbling]: http://www.railsbling.com
[📜src-gh-img]: https://img.shields.io/badge/GitHub-238636?style=for-the-badge&logo=Github&logoColor=green
[📜src-gh]: https://github.com/omniauth/omniauth-ldap
[📜docs-cr-rd-img]: https://img.shields.io/badge/RubyDoc-Current_Release-943CD2?style=for-the-badge&logo=readthedocs&logoColor=white
[📜docs-head-rd-img]: https://img.shields.io/badge/YARD_on_Galtzo.com-HEAD-943CD2?style=for-the-badge&logo=readthedocs&logoColor=white
[📜gh-wiki]: https://github.com/omniauth/omniauth-ldap/wiki
[📜gh-wiki-img]: https://img.shields.io/badge/wiki-examples-943CD2.svg?style=for-the-badge&logo=github&logoColor=white
[👽dl-rank]: https://bestgems.org/gems/omniauth-ldap
[👽dl-ranki]: https://img.shields.io/gem/rd/omniauth-ldap.svg
[👽oss-help]: https://www.codetriage.com/omniauth/omniauth-ldap
[👽oss-helpi]: https://www.codetriage.com/omniauth/omniauth-ldap/badges/users.svg
[👽version]: https://bestgems.org/gems/omniauth-ldap
[👽versioni]: https://img.shields.io/gem/v/omniauth-ldap.svg
[🏀codecov]: https://codecov.io/gh/omniauth/omniauth-ldap
[🏀codecovi]: https://codecov.io/gh/omniauth/omniauth-ldap/graph/badge.svg
[🏀coveralls]: https://coveralls.io/github/omniauth/omniauth-ldap?branch=main
[🏀coveralls-img]: https://coveralls.io/repos/github/omniauth/omniauth-ldap/badge.svg?branch=main
[🖐codeQL]: https://github.com/omniauth/omniauth-ldap/security/code-scanning
[🖐codeQL-img]: https://github.com/omniauth/omniauth-ldap/actions/workflows/codeql-analysis.yml/badge.svg
[🚎1-an-wf]: https://github.com/omniauth/omniauth-ldap/actions/workflows/ancient.yml
[🚎1-an-wfi]: https://github.com/omniauth/omniauth-ldap/actions/workflows/ancient.yml/badge.svg
[🚎2-cov-wf]: https://github.com/omniauth/omniauth-ldap/actions/workflows/coverage.yml
[🚎2-cov-wfi]: https://github.com/omniauth/omniauth-ldap/actions/workflows/coverage.yml/badge.svg
[🚎3-hd-wf]: https://github.com/omniauth/omniauth-ldap/actions/workflows/heads.yml
[🚎3-hd-wfi]: https://github.com/omniauth/omniauth-ldap/actions/workflows/heads.yml/badge.svg
[🚎4-lg-wf]: https://github.com/omniauth/omniauth-ldap/actions/workflows/legacy.yml
[🚎4-lg-wfi]: https://github.com/omniauth/omniauth-ldap/actions/workflows/legacy.yml/badge.svg
[🚎5-st-wf]: https://github.com/omniauth/omniauth-ldap/actions/workflows/style.yml
[🚎5-st-wfi]: https://github.com/omniauth/omniauth-ldap/actions/workflows/style.yml/badge.svg
[🚎6-s-wf]: https://github.com/omniauth/omniauth-ldap/actions/workflows/supported.yml
[🚎6-s-wfi]: https://github.com/omniauth/omniauth-ldap/actions/workflows/supported.yml/badge.svg
[🚎7-us-wf]: https://github.com/omniauth/omniauth-ldap/actions/workflows/unsupported.yml
[🚎7-us-wfi]: https://github.com/omniauth/omniauth-ldap/actions/workflows/unsupported.yml/badge.svg
[🚎8-ho-wf]: https://github.com/omniauth/omniauth-ldap/actions/workflows/hoary.yml
[🚎8-ho-wfi]: https://github.com/omniauth/omniauth-ldap/actions/workflows/hoary.yml/badge.svg
[🚎9-t-wf]: https://github.com/omniauth/omniauth-ldap/actions/workflows/truffle.yml
[🚎9-t-wfi]: https://github.com/omniauth/omniauth-ldap/actions/workflows/truffle.yml/badge.svg
[🚎10-j-wf]: https://github.com/omniauth/omniauth-ldap/actions/workflows/jruby.yml
[🚎10-j-wfi]: https://github.com/omniauth/omniauth-ldap/actions/workflows/jruby.yml/badge.svg
[🚎11-c-wf]: https://github.com/omniauth/omniauth-ldap/actions/workflows/current.yml
[🚎11-c-wfi]: https://github.com/omniauth/omniauth-ldap/actions/workflows/current.yml/badge.svg
[🚎12-crh-wf]: https://github.com/omniauth/omniauth-ldap/actions/workflows/dep-heads.yml
[🚎12-crh-wfi]: https://github.com/omniauth/omniauth-ldap/actions/workflows/dep-heads.yml/badge.svg
[🚎13-🔒️-wf]: https://github.com/omniauth/omniauth-ldap/actions/workflows/locked_deps.yml
[🚎13-🔒️-wfi]: https://github.com/omniauth/omniauth-ldap/actions/workflows/locked_deps.yml/badge.svg
[🚎14-🔓️-wf]: https://github.com/omniauth/omniauth-ldap/actions/workflows/unlocked_deps.yml
[🚎14-🔓️-wfi]: https://github.com/omniauth/omniauth-ldap/actions/workflows/unlocked_deps.yml/badge.svg
[🚎15-🪪-wf]: https://github.com/omniauth/omniauth-ldap/actions/workflows/license-eye.yml
[🚎15-🪪-wfi]: https://github.com/omniauth/omniauth-ldap/actions/workflows/license-eye.yml/badge.svg
[💎ruby-2.0i]: https://img.shields.io/badge/Ruby-2.0_(%F0%9F%9A%ABCI)-AABBCC?style=for-the-badge&logo=ruby&logoColor=white
[💎ruby-2.1i]: https://img.shields.io/badge/Ruby-2.1_(%F0%9F%9A%ABCI)-AABBCC?style=for-the-badge&logo=ruby&logoColor=white
[💎ruby-2.2i]: https://img.shields.io/badge/Ruby-2.2_(%F0%9F%9A%ABCI)-AABBCC?style=for-the-badge&logo=ruby&logoColor=white
[💎ruby-2.3i]: https://img.shields.io/badge/Ruby-2.3-DF00CA?style=for-the-badge&logo=ruby&logoColor=white
[💎ruby-2.4i]: https://img.shields.io/badge/Ruby-2.4-DF00CA?style=for-the-badge&logo=ruby&logoColor=white
[💎ruby-2.5i]: https://img.shields.io/badge/Ruby-2.5-DF00CA?style=for-the-badge&logo=ruby&logoColor=white
[💎ruby-2.6i]: https://img.shields.io/badge/Ruby-2.6-DF00CA?style=for-the-badge&logo=ruby&logoColor=white
[💎ruby-2.7i]: https://img.shields.io/badge/Ruby-2.7-DF00CA?style=for-the-badge&logo=ruby&logoColor=white
[💎ruby-3.0i]: https://img.shields.io/badge/Ruby-3.0-CC342D?style=for-the-badge&logo=ruby&logoColor=white
[💎ruby-3.1i]: https://img.shields.io/badge/Ruby-3.1-CC342D?style=for-the-badge&logo=ruby&logoColor=white
[💎ruby-3.2i]: https://img.shields.io/badge/Ruby-3.2-CC342D?style=for-the-badge&logo=ruby&logoColor=white
[💎ruby-3.3i]: https://img.shields.io/badge/Ruby-3.3-CC342D?style=for-the-badge&logo=ruby&logoColor=white
[💎ruby-c-i]: https://img.shields.io/badge/Ruby-current-CC342D?style=for-the-badge&logo=ruby&logoColor=green
[💎ruby-headi]: https://img.shields.io/badge/Ruby-HEAD-CC342D?style=for-the-badge&logo=ruby&logoColor=blue
[💎truby-22.3i]: https://img.shields.io/badge/Truffle_Ruby-22.3_(%F0%9F%9A%ABCI)-AABBCC?style=for-the-badge&logo=ruby&logoColor=pink
[💎truby-23.0i]: https://img.shields.io/badge/Truffle_Ruby-23.0_(%F0%9F%9A%ABCI)-AABBCC?style=for-the-badge&logo=ruby&logoColor=pink
[💎truby-23.1i]: https://img.shields.io/badge/Truffle_Ruby-23.1-34BCB1?style=for-the-badge&logo=ruby&logoColor=pink
[💎truby-c-i]: https://img.shields.io/badge/Truffle_Ruby-current-34BCB1?style=for-the-badge&logo=ruby&logoColor=green
[💎truby-headi]: https://img.shields.io/badge/Truffle_Ruby-HEAD-34BCB1?style=for-the-badge&logo=ruby&logoColor=blue
[💎jruby-9.1i]: https://img.shields.io/badge/JRuby-9.1_(%F0%9F%9A%ABCI)-AABBCC?style=for-the-badge&logo=ruby&logoColor=red
[💎jruby-9.2i]: https://img.shields.io/badge/JRuby-9.2_(%F0%9F%9A%ABCI)-AABBCC?style=for-the-badge&logo=ruby&logoColor=red
[💎jruby-9.3i]: https://img.shields.io/badge/JRuby-9.3_(%F0%9F%9A%ABCI)-AABBCC?style=for-the-badge&logo=ruby&logoColor=red
[💎jruby-9.4i]: https://img.shields.io/badge/JRuby-9.4-FBE742?style=for-the-badge&logo=ruby&logoColor=red
[💎jruby-c-i]: https://img.shields.io/badge/JRuby-current-FBE742?style=for-the-badge&logo=ruby&logoColor=green
[💎jruby-headi]: https://img.shields.io/badge/JRuby-HEAD-FBE742?style=for-the-badge&logo=ruby&logoColor=blue
[🤝gh-issues]: https://github.com/omniauth/omniauth-ldap/issues
[🤝gh-pulls]: https://github.com/omniauth/omniauth-ldap/pulls
[🤝contributing]: CONTRIBUTING.md
[🏀codecov-g]: https://codecov.io/gh/omniauth/omniauth-ldap/graphs/tree.svg
[🖐contrib-rocks]: https://contrib.rocks
[🖐contributors]: https://github.com/omniauth/omniauth-ldap/graphs/contributors
[🖐contributors-img]: https://contrib.rocks/image?repo=omniauth/omniauth-ldap
[🪇conduct]: CODE_OF_CONDUCT.md
[🪇conduct-img]: https://img.shields.io/badge/Contributor_Covenant-2.1-259D6C.svg
[📌pvc]: http://guides.rubygems.org/patterns/#pessimistic-version-constraint
[📌semver]: https://semver.org/spec/v2.0.0.html
[📌semver-img]: https://img.shields.io/badge/semver-2.0.0-259D6C.svg?style=flat
[📌semver-breaking]: https://github.com/semver/semver/issues/716#issuecomment-869336139
[📌major-versions-not-sacred]: https://tom.preston-werner.com/2022/05/23/major-version-numbers-are-not-sacred.html
[📌changelog]: CHANGELOG.md
[📗keep-changelog]: https://keepachangelog.com/en/1.0.0/
[📗keep-changelog-img]: https://img.shields.io/badge/keep--a--changelog-1.0.0-34495e.svg?style=flat
[📌gitmoji]: https://gitmoji.dev
[📌gitmoji-img]: https://img.shields.io/badge/gitmoji_commits-%20%F0%9F%98%9C%20%F0%9F%98%8D-34495e.svg?style=flat-square
[🧮kloc]: https://www.youtube.com/watch?v=dQw4w9WgXcQ
[🧮kloc-img]: https://img.shields.io/badge/KLOC-0.293-FFDD67.svg?style=for-the-badge&logo=YouTube&logoColor=blue
[🔐security]: SECURITY.md
[🔐security-img]: https://img.shields.io/badge/security-policy-259D6C.svg?style=flat
[📄copyright-notice-explainer]: https://opensource.stackexchange.com/questions/5778/why-do-licenses-such-as-the-mit-license-specify-a-single-year
[📄license]: LICENSE.txt
[📄license-ref]: https://opensource.org/licenses/MIT
[📄license-img]: https://img.shields.io/badge/License-MIT-259D6C.svg
[📄license-compat]: https://dev.to/galtzo/how-to-check-license-compatibility-41h0
[📄license-compat-img]: https://img.shields.io/badge/Apache_Compatible:_Category_A-%E2%9C%93-259D6C.svg?style=flat&logo=Apache
[📄ilo-declaration]: https://www.ilo.org/declaration/lang--en/index.htm
[📄ilo-declaration-img]: https://img.shields.io/badge/ILO_Fundamental_Principles-✓-259D6C.svg?style=flat
[🚎yard-current]: http://rubydoc.info/gems/omniauth-ldap
[🚎yard-head]: https://omniauth-ldap.galtzo.com
[💎stone_checksums]: https://github.com/galtzo-floss/stone_checksums
[💎SHA_checksums]: https://gitlab.com/omniauth/omniauth-ldap/-/tree/main/checksums
[💎rlts]: https://github.com/rubocop-lts/rubocop-lts
[💎rlts-img]: https://img.shields.io/badge/code_style_&_linting-rubocop--lts-34495e.svg?plastic&logo=ruby&logoColor=white
[💎appraisal2]: https://github.com/appraisal-rb/appraisal2
[💎appraisal2-img]: https://img.shields.io/badge/appraised_by-appraisal2-34495e.svg?plastic&logo=ruby&logoColor=white
[💎d-in-dvcs]: https://railsbling.com/posts/dvcs/put_the_d_in_dvcs/

[//]: # (LDAP RFC references)
[rfc4511]: https://datatracker.ietf.org/doc/html/rfc4511
[rfc4514]: https://datatracker.ietf.org/doc/html/rfc4514
[rfc4519]: https://datatracker.ietf.org/doc/html/rfc4519
