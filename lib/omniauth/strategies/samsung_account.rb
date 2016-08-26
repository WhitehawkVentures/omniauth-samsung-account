# encoding: UTF-8

require 'omniauth-oauth2'
require 'json'
require 'net/http'

module OmniAuth
  module Strategies
    class SamsungAccount < OmniAuth::Strategies::OAuth2
      TOKEN_URL_PATH = "/auth/oauth2/token"
      TOKEN_VALIDATE_PATH = "/v2/license/security/authorizeToken"
      PROFILE_PATH = "/v2/profile/user/user"
      PROXY_HOST = "samsung.touchofmodern.com"

      option :name, "samsung_account"

      option :provider_ignores_state, true
      option :client_options, {
        :site => "https://api.samsungosp.com",
        :authorize_url => "https://us.account.samsung.com/account/check.do",
        :token_url => "https://#{PROXY_HOST}/auth.samsungosp.com#{TOKEN_URL_PATH}"
      }
      option :gateway, nil
      option :scope, "3RD_PARTY"
      option :country_code, "US"
      option :language_code, "en"
      option :service_channel, "PC_PARTNER"
      option :go_back_url, nil

      uid {
        raw_info["userId"]
      }

      credentials do
        hash = {"token" => access_token.token}
        hash.merge!("refresh_token" => access_token.refresh_token)
        hash.merge!("expires_at" => access_token.expires_at)
        hash.merge!("refresh_token_expires_at" => Time.now.to_i + access_token.params["refresh_token_expires_in"].to_i)
        hash.merge!("expires" => access_token.expires?)

        hash.merge!("user_id" => access_token.params["userId"])
        hash.merge!("api_server_url" => access_token.params["api_server_url"])
        hash.merge!("auth_server_url" => access_token.params["auth_server_url"])
        hash
      end

      info do
        hash = {}
        hash["email"] = raw_info["UserVO"]["userIdentificationVO"]["loginID"]
        hash["first_name"] = raw_info["UserVO"]["userBaseVO"]["userBaseIndividualVO"]["givenName"]
        hash["last_name"] = raw_info["UserVO"]["userBaseVO"]["userBaseIndividualVO"]["familyName"]
        hash["birthday"] = raw_info["UserVO"]["userBaseVO"]["userBaseIndividualVO"]["birthDate"]
        hash
        prune! hash
      end

      extra do
        hash = {}
        hash['raw_info'] = raw_info unless skip_info?
        prune! hash
      end

      def request_phase
        c = client
        gateway = (request.params["gateway"] || options.gateway ||
                   request.params["country_code"] || options.country_code)
        case gateway.downcase
        when "us"
          c.options[:authorize_url] = "https://us.account.samsung.com/account/check.do"
        when "eu"
          c.options[:authorize_url] = "https://account.samsung.com/account/check.do"
        when "cn"
          c.options[:authorize_url] = "https://account.samsung.cn/account/check.do"
        end
        params = {
          "redirect_uri" => callback_url,
          "actionID" => "StartAP",
          "serviceID" => options.client_id,
          "countryCode" => options.country_code,
          "languageCode" => options.language_code,
          "serviceChannel" => options.service_channel
        }.merge(authorize_params)
        params["goBackURL"] = options.go_back_url if options.go_back_url
        redirect c.authorize_url(params)
      end

      def raw_info
        @raw_info ||= begin
          access_token.options.merge!({
                                          header_format: "Basic #{Base64.strict_encode64("#{client.id}:#{client.secret}")}",
                                          param_name: 'access_token'
                                      })
          response = access_token.get(TOKEN_VALIDATE_PATH, {
              :params => {
                  :authToken => access_token.token
              },
              :headers => {
                  "x-osp-appId" => client.id
              }
          }).parsed || {}
          guid = response["AuthorizeTokenResultVO"]["authenticateUserID"]
          results = access_token.get("#{PROFILE_PATH}/#{guid}", { :headers => { "x-osp-appId" => access_token.client.id, "x-osp-userId" => guid } }).parsed || {}
          results.merge("userId" => guid)
        end
      end

      protected
      def prune!(hash)
        hash.delete_if do |_, value|
          prune!(value) if value.is_a?(Hash)
          value.nil? || (value.respond_to?(:empty?) && value.empty?)
        end
      end

      def build_samsung_access_token
        client = self.client

        if request.params["access_token"]
          token = ::OAuth2::AccessToken.new(
              client, request.params["access_token"],
              :expires_at => Time.now.to_i + 86400,
              :expires_in => 86400,
              :refresh_token => "-1",
              :random => 1
          )
          return token
        end

        json = JSON.parse(request.params["code"])
        code = json["code"]
        scope = json["scode"]
        email = json["inputEmailID"]
        api_server_url = json["api_server_url"]
        auth_server_url = json["auth_server_url"]
        closed_action = json["closedAction"]

        base_params = {
          :client_id => options.client_id,
          :client_secret => options.client_secret
        }

        # Create a local var so we mutate a given client instance.
        client.options[:token_url] = "https://%s%s" % [auth_server_url, TOKEN_URL_PATH]
        token = client.auth_code.get_token(code, base_params.merge(token_params.to_hash(:symbolize_keys => true)), deep_symbolize(options.auth_token_params))
        token.params["email"] = email
        token.params["api_server_url"] = api_server_url
        token.params["auth_server_url"] = auth_server_url
        return token
      end
      alias_method :build_access_token, :build_samsung_access_token
    end
  end
end
