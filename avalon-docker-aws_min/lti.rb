module OmniAuth
  module Strategies
    class Lti
      include OmniAuth::Strategy
      
      # Hash for storing your Consumer Tools credentials, whether:
      # - the key is the consumer_key 
      # - the value is the comsumer_secret
      option :oauth_credentials, {}

      option :consumers, {}
      
      def callback_phase
        byebug
        key = request.params['oauth_consumer_key']
        secret = options.oauth_credentials.nil? ? nil : options.oauth_credentials[key]
        @tp = IMS::LTI::ToolProvider.new(key, secret, request.params)
        env['lti.launch_params'] = @tp.to_params
        @tp.valid_request! request
        @consumer = options.consumers[@tp.tool_consumer_instance_guid] || {}
        super
      rescue ::OAuth::Unauthorized => e
        #Don't pass the exception to fail! because it isn't well formed
        fail!(:invalid_credentials)
      end
      
      # define the UID
      uid { lookup(:uid, @tp.user_id) }
      
      # define the hash of info about user
      info do
        {
          :name => lookup(:name, uid),
          :email => lookup(:email, @tp.lis_person_contact_email_primary),
          :first_name => lookup(:first_name, @tp.lis_person_name_given),
          :last_name => lookup(:last_name, @tp.lis_person_name_family),
          :image => lookup(:image, @tp.user_image)
        }
      end
      
      # define the hash of credentials
      credentials do
        {
          :token => @tp.consumer_key,
          :secret => @tp.consumer_secret
        }
      end
      
      #define extra hash
      extra do
        {
           :context_id => lookup(:context_id, @tp.context_id),
           :context_name => lookup(:context_name, @tp.context_label),
           :raw_info => @tp.to_params,
           :consumer => @consumer.keys.inject({}) { |result, key| result[key] = lookup(key, nil); result }
        }
      end

      def lookup(field, default = nil)
        result = default unless @consumer[field.to_s].present?
        result ||= @tp.send(@consumer[field.to_s]) rescue nil
        result ||= @tp.custom_params[@consumer[field.to_s].to_s] rescue nil
        result
      end
    end
  end
end
