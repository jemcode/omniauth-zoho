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

      private

      def callback_url
        options[:redirect_uri] || (full_host + script_name + callback_path)
      end
    end
  end
end
