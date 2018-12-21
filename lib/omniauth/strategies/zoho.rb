require 'omniauth/strategies/oauth2'

module OmniAuth
  module Strategies
    class Zoho < OmniAuth::Strategies::OAuth2

      option :client_options, {
          :site          => 'https://accounts.zoho.com',
          :authorize_url => '/oauth/v2/auth',
          :token_url     => '/oauth/v2/token'
      }

      option provider_ignores_state: true

      def authorize_params
        super.merge(access_type: request.params["access_type"])
      end
      
      credentials do
        hash = {"token" => access_token.token}
        hash.merge!("refresh_token" => access_token.refresh_token) if access_token.expires? && access_token.refresh_token
        hash.merge!("expires_at" => Time.now.to_i + 3600)
        hash.merge!("expires" => true)
        hash
      end

      private

      def callback_url
        options[:redirect_uri] || (full_host + script_name + callback_path)
      end
    end
  end
end
