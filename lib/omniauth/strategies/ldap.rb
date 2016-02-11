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

      def request_phase
        OmniAuth::LDAP::Adaptor.validate @options
        f = OmniAuth::Form.new(:title => (options[:title] || "LDAP Authentication"), :url => callback_path)
        f.text_field 'Login', 'username'
        f.password_field 'Password', 'password'
        f.button "Sign In"
        f.to_response
      end

      def callback_phase
        username_elems = @options[:name_proc].call(request['username']).split('\\')
        options = @options.dup
        if (username_elems.length == 2)
          # Create a shallow copy of the options
          options = @options.dup
          # In our copy of the hash, we modify the base DN; we prefix a DC=subdomain string
          # An example would be : 
          #     for  base: DC=example,DC=com and usename emea\user1  this would become
          #          base: DC=emea,DC=example,DC=com and we would authenticate username user1 
          #                on the emea subdomain.
          # This would allow for the same username across multiple subdomains,
          # something unhealthy but which seems to occur.
          # For example emea\user1 and us\user1 to work across a higher level domain controller.
          options[:base] = 'DC=%s,%s' % [ username_elems[0], @options[:base] ]
          username = username_elems[1]
        else
          # Fallback to the standard behavior here
          username = request['username']
        end
        @adaptor = OmniAuth::LDAP::Adaptor.new options

        return fail!(:missing_credentials) if missing_credentials?
        begin
          @ldap_user_info = @adaptor.bind_as(:filter => filter(@adaptor), :size => 1, :password => request['password'])
          return fail!(:invalid_credentials) if !@ldap_user_info

          @user_info = self.class.map_user(@@config, @ldap_user_info)
          super
        rescue Exception => e
          return fail!(:ldap_error, e)
        end
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
        { :raw_info => @ldap_user_info }
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
    end
  end
end

OmniAuth.config.add_camelization 'ldap', 'LDAP'
