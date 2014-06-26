require 'omniauth'

module OmniAuth
  module Strategies
    class LDAP
      include OmniAuth::Strategy
      @@config = {
        'name' => 'cn',
        'first_name' => 'givenName',
        'last_name' => 'sn',
        'email' => ['mail', "email", 'userPrincipalName'],
        'phone' => ['telephoneNumber', 'homePhone', 'facsimileTelephoneNumber'],
        'mobile' => ['mobile', 'mobileTelephoneNumber'],
        'nickname' => ['uid', 'userid', 'sAMAccountName'],
        'title' => 'title',
        'location' => {"%0, %1, %2, %3 %4" => [['address', 'postalAddress', 'homePostalAddress', 'street', 'streetAddress'], ['l'], ['st'],['co'],['postOfficeBox']]},
        'uid' => 'dn',
        'url' => ['wwwhomepage'],
        'image' => 'jpegPhoto',
        'description' => 'description'
      }
      option :title, "LDAP Authentication" #default title for authentication form
      option :port, 389
      option :method, :plain
      option :uid, 'sAMAccountName'
      option :name_proc, lambda {|n| n}
      option :group_query, nil
      option :group_attribute, 'cn'

      def request_phase
        OmniAuth::LDAP::Adaptor.validate @options
        f = OmniAuth::Form.new(:title => (options[:title] || "LDAP Authentication"), :url => callback_path)
        f.text_field 'Login', 'username'
        f.password_field 'Password', 'password'
        f.button "Sign In"
        f.to_response
      end

      def callback_phase
        @adaptor = OmniAuth::LDAP::Adaptor.new @options

        return fail!(:missing_credentials) if missing_credentials?
        begin
          @ldap_user_info = @adaptor.bind_as(:filter => filter(@adaptor), :size => 1, :password => request['password'])
          return fail!(:invalid_credentials) if !@ldap_user_info

          # I [aocole] believe there is a bug in the Net::LDAP library that
          # improperly encodes utf_8 as ASCII-8BIT when it receives unicode
          # from the LDAP server. Fix it up here because I don't have time
          # to track it down in Net::LDAP
          fix_encoding!(@ldap_user_info)

          # execute groups query
          @groups = group_query(@adaptor, @ldap_user_info)
          
          @user_info = self.class.map_user(@@config, @ldap_user_info)
          super
        rescue Exception => e
          return fail!(:ldap_error, e)
        end
      end

      def group_query adaptor, ldap_user_info
        return nil unless adaptor.group_query and !adaptor.group_query.empty?

        uid = ldap_user_info[@options[:uid].intern].first
        dn = ldap_user_info[:dn].first
        groups = adaptor.search(filter: adaptor.group_query % {username: Net::LDAP::Filter.escape(uid), dn: Net::LDAP::Filter.escape(dn)})
        groups.collect!{|g|g[options[:group_attribute].intern].first}
        return groups
      end

      def filter adaptor
        if adaptor.filter and !adaptor.filter.empty?
          Net::LDAP::Filter.construct(adaptor.filter % {username: @options[:name_proc].call(request['username'])})
        else
          Net::LDAP::Filter.eq(adaptor.uid, @options[:name_proc].call(request['username']))
        end
      end

      uid {
        @user_info["uid"]
      }
      info {
        @user_info
      }
      extra {
        ex = { :raw_info => @ldap_user_info }
        ex[:groups] = @groups if @groups
        ex
      }

      def self.map_user(mapper, object)
        user = {}
        mapper.each do |key, value|
          case value
          when String
            user[key] = object[value.downcase.to_sym].first if object.respond_to? value.downcase.to_sym
          when Array
            value.each {|v| (user[key] = object[v.downcase.to_sym].first; break;) if object.respond_to? v.downcase.to_sym}
          when Hash
            value.map do |key1, value1|
              pattern = key1.dup
              value1.each_with_index do |v,i|
                part = ''; v.collect(&:downcase).collect(&:to_sym).each {|v1| (part = object[v1].first; break;) if object.respond_to? v1}
                pattern.gsub!("%#{i}",part||'')
              end
              user[key] = pattern
            end
          end
        end
        user
      end

      protected

      def missing_credentials?
        request['username'].nil? or request['username'].empty? or request['password'].nil? or request['password'].empty?
      end # missing_credentials?


      # This is written a little strangely because we can't modify the object in-place due
      # to frozen strings used in rspec stubs. Thus, the Hash and Array cases re-assign their
      # contents, while the String case returns a new String.
      def fix_encoding!(thing)
        case thing
        when Net::LDAP::Entry
          thing.each_attribute do |k|
            fix_encoding!(thing[k])
          end
        when Hash
          thing.each_pair do |k, v|
            thing[k] = fix_encoding!(v)
          end
        when Array
          thing.collect! do |v|
            fix_encoding!(v)
          end
        when String
          sanitize_utf8(thing)
        end
      end

      def sanitize_utf8(str)
        str = str.dup
        if str.force_encoding(Encoding::UTF_8).valid_encoding?
          return str # has been forced to utf-8
        end

        return str.encode(Encoding::UTF_8, "binary",
                           :invalid => :replace,
                           :undef   => :replace,
                           :replace => "")
      end

    end
  end
end

OmniAuth.config.add_camelization 'ldap', 'LDAP'
