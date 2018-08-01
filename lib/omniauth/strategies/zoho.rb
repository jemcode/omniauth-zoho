require 'omniauth/strategies/oauth2'

module OmniAuth
  module Strategies
    class Zoho < OmniAuth::Strategies::OAuth2

      option :client_options, {
          :site          => 'https://accounts.zoho.com',
          :authorize_url => '/oauth/v2/auth',
          :token_url     => '/oauth/v2/token'
      }

      option authorize_params: {
          :access_type => 'online'
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

      def raw_info
        @raw_info ||= access_token.get('https://www.zohoapis.com/crm/v2/org').parsed['org'].first
      end
    end
  end
end