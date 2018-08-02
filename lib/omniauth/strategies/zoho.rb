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

      uid{ raw_info['id'] }

      info do
        {
            :email => raw_info['primary_email'],
        }
      end

      extra do
        {
            'raw_info' => raw_info
        }
      end

      credentials do
        hash = {"token" => access_token.token}
        hash.merge!("refresh_token" => access_token.refresh_token) if access_token.expires? && access_token.refresh_token
        hash.merge!("expires_at" => Time.now.to_i + 3600)
        hash.merge!("expires" => true)
        hash
      end

      def raw_info
        @raw_info ||= access_token.get('https://www.zohoapis.com/crm/v2/org').parsed['org'].first
      end
    end
  end
end