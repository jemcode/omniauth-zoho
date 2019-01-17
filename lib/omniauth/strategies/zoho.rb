require 'omniauth/strategies/oauth2'

module OmniAuth
  module Strategies
    class Zoho < OmniAuth::Strategies::OAuth2

      option :client_options, {
        site: 'https://accounts.zoho.com',
        authorize_url: '/oauth/v2/auth',
        token_url: '/oauth/v2/token',
      }

      option provider_ignores_state: true

      option :authorize_options, %i[access_type prompt response_type scope]

      def authorize_params
        super.tap do |params|
          params[:access_type] = 'offline' if params[:access_type].nil?
          params[:prompt] = 'consent'
          params[:response_type] = 'code'
          params[:scope] = params[:scope]
        end
      end

      uid { raw_info["organization_id"] }

      credentials do
        hash = {"token" => access_token.token}
        hash["refresh_token"] = access_token.refresh_token if access_token.expires? && access_token.refresh_token
        hash["expires_at"] = access_token.expires_at if access_token.expires?
        hash["expires"] = access_token.expires?
        hash
      end

      extra do
        {
          raw_info: raw_info
        }
      end

      def raw_info
        @raw_info ||= access_token.get('https://books.zoho.com/api/v3/organizations',
          { headers: { 'Authorization' => "Zoho-authtoken #{credentials["token"]}" }}
        ).parsed
      end

      private

      def callback_url
        options[:redirect_uri] || (full_host + script_name + callback_path)
      end
    end
  end
end
