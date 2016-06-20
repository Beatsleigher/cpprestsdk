/***
* ==++==
*
* Copyright (c) Microsoft Corporation. All rights reserved.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* ==--==
* =+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
*
* HTTP Library: Oauth 2.0
*
* For the latest on this and related APIs, please see: https://github.com/Microsoft/cpprestsdk
*
* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
****/

#include "stdafx.h"
#include "cpprest/oauth2.h"

using web::http::client::http_client;
using web::http::client::http_client_config;
using web::http::oauth2::details::oauth2_strings;
using web::http::details::mime_types;
using utility::conversions::to_utf8string;

// Expose base64 conversion for arbitrary buffer.
extern utility::string_t _to_base64(const unsigned char *ptr, size_t size);

namespace web { namespace http { namespace oauth2
{

namespace details
{

#define _OAUTH2_STRINGS
#define DAT(a_, b_) const utility::string_t oauth2_strings::a_(_XPLATSTR(b_));
#include "cpprest/details/http_constants.dat"
#undef _OAUTH2_STRINGS
#undef DAT

} // namespace web::http::oauth2::details

namespace experimental
{

namespace details
{

    namespace
    {
        struct oauth2_pipeline_stage;
    }

    class oauth2_shared_token
    {
    private:
        mutable std::mutex m_lock;
        oauth2_token m_token;

        friend struct details::oauth2_pipeline_stage;

    public:
        oauth2_shared_token(const oauth2_token& tok) : m_token(tok) {}

        void set_token(oauth2_token tok)
        {
            std::lock_guard<std::mutex> lock(m_lock);
            m_token = std::move(tok);
        }
        oauth2_token token() const
        {
            oauth2_token tok;
            {
                std::lock_guard<std::mutex> lock(m_lock);
                tok = m_token;
            }
            return tok;
        }
    };

namespace
{
    struct oauth2_pipeline_stage : public http_pipeline_stage
    {
        oauth2_pipeline_stage(
            authenticated_request_mode request_mode,
            const utility::string_t& access_token_key,
            std::shared_ptr<oauth2_shared_token> token)
            : m_request_mode(request_mode)
            , m_access_token_key(access_token_key)
            , m_token(std::move(token))
        {}

        const authenticated_request_mode m_request_mode;
        const utility::string_t m_access_token_key;
        std::shared_ptr<oauth2_shared_token> m_token;

        virtual pplx::task<http_response> propagate(http_request request) override
        {
            if (m_request_mode == authenticated_request_mode::authorization_header_field)
            {
                utility::string_t auth_hdr = _XPLATSTR("Bearer ");
                {
                    std::lock_guard<std::mutex> lock(m_token->m_lock);
                    auth_hdr += m_token->m_token.access_token();
                }
                request.headers().add(header_names::authorization, auth_hdr);
            }
            else
            {
                uri_builder ub(request.request_uri());
                utility::string_t access_token;
                {
                    std::lock_guard<std::mutex> lock(m_token->m_lock);
                    access_token = m_token->m_token.access_token();
                }
                ub.append_query(m_access_token_key, access_token);
                request.set_request_uri(ub.to_uri());
            }
            return next_stage()->propagate(request);
        }
    };
}}

oauth2_client::oauth2_client(const oauth2_token& token)
    : m_impl(std::make_shared<details::oauth2_shared_token>(token))
{}

oauth2_client::~oauth2_client() {}

void oauth2_client::set_token(const oauth2_token& tok)
{
    m_impl->set_token(tok);
}

oauth2_token oauth2_client::token() const
{
    return m_impl->token();
}

namespace
{
    web::uri build_authorization_uri(
        uri_builder user_agent_base_uri,
        const utility::string_t& client_id,
        const utility::string_t& redirect_uri,
        const utility::string_t& state_cookie,
        const utility::string_t& scope)
    {
        user_agent_base_uri.append_query(oauth2_strings::client_id, client_id);
        user_agent_base_uri.append_query(oauth2_strings::redirect_uri, redirect_uri);
        user_agent_base_uri.append_query(oauth2_strings::state, state_cookie);

        if (!scope.empty())
        {
            user_agent_base_uri.append_query(oauth2_strings::scope, scope);
        }
        return user_agent_base_uri.to_uri();
    }

    oauth2_token parse_token_from_json(const json::value& token_json, const utility::string_t& default_scope)
    {
        oauth2_token result;

        if (token_json.has_field(oauth2_strings::access_token))
        {
            result.set_access_token(utility::conversions::to_string_t(token_json.at(oauth2_strings::access_token).as_string()));
        }
        else
        {
            throw oauth2_exception("response json contains no 'access_token': " + token_json.serialize());
        }

        if (token_json.has_field(oauth2_strings::token_type))
        {
            result.set_token_type(utility::conversions::to_string_t(token_json.at(oauth2_strings::token_type).as_string()));
        }
        else
        {
            // Some services don't return 'token_type' while it's required by OAuth 2.0 spec:
            // http://tools.ietf.org/html/rfc6749#section-5.1
            // As workaround we act as if 'token_type=bearer' was received.
            result.set_token_type(oauth2_strings::bearer);
        }
        if (!utility::details::str_icmp(result.token_type(), oauth2_strings::bearer))
        {
            throw oauth2_exception("only 'token_type=bearer' access tokens are currently supported: " + token_json.serialize());
        }

        if (token_json.has_field(oauth2_strings::refresh_token))
        {
            result.set_refresh_token(utility::conversions::to_string_t(token_json.at(oauth2_strings::refresh_token).as_string()));
        }
        else
        {
            // Do nothing. Preserves the old refresh token.
        }

        if (token_json.has_field(oauth2_strings::expires_in))
        {
            const auto &json_expires_in_val = token_json.at(oauth2_strings::expires_in);

            if (json_expires_in_val.is_number())
                result.set_expires_in(json_expires_in_val.as_number().to_int64());
            else
            {
                // Handle the case of a number as a JSON "string".
                // Using streams because std::stoll isn't avaliable on Android.
                int64_t expires = utility::details::scan_string<int64_t>(json_expires_in_val.as_string());
                result.set_expires_in(expires);
            }
        }
        else
        {
            result.set_expires_in(oauth2_token::undefined_expiration);
        }

        if (token_json.has_field(oauth2_strings::scope))
        {
            // The authorization server may return different scope from the one requested.
            // See: http://tools.ietf.org/html/rfc6749#section-3.3
            result.set_scope(utility::conversions::to_string_t(token_json.at(oauth2_strings::scope).as_string()));
        }
        else
        {
            // Use the requested scope() if no scope parameter was returned.
            result.set_scope(default_scope);
        }

        return result;
    }

    pplx::task<web::uri> communicate_with_user_agent(
        const web::uri& user_agent_url,
        const web::uri& local_uri,
        const oauth2_client::launch_user_agent_callback& launch_user_agent)
    {
        auto listener = std::make_shared<web::http::experimental::listener::http_listener>(local_uri);
        return listener->open().then([listener, user_agent_url, launch_user_agent]()
        {
            pplx::task_completion_event<web::uri> tce;

            listener->support([tce](http::http_request request) -> void
            {
                tce.set(request.request_uri());
                request.reply(status_codes::OK, U("Ok."));
            });

            launch_user_agent(user_agent_url, tce);

            auto t = pplx::create_task(tce);
            t.then([listener](const web::uri&) {
                return listener->close();
            }
            ).then([](pplx::task<void> t2)
            {
                try
                {
                    t2.get();
                }
                catch (...) {}
            });
            return t;
        });
    }

    void check_state_cookie(const std::map<utility::string_t, utility::string_t>& query_map, const utility::string_t& state_cookie)
    {
        auto state_param = query_map.find(oauth2_strings::state);
        if (state_param == query_map.end())
        {
            throw oauth2_exception("parameter 'state' missing from redirected URI.");
        }

        if (state_cookie != state_param->second)
        {
            std::string err;
            err.append("redirected URI parameter 'state'='");
            err.append(utility::conversions::to_utf8string(state_param->second));
            err.append("' does not match state='");
            err.append(utility::conversions::to_utf8string(state_cookie));
            err.append("'.");
            throw oauth2_exception(err);
        }
    }

    void append_client_credentials(http_request& request, uri_builder& request_body, const web::credentials& creds, client_credentials_mode mode)
    {
        if (mode == client_credentials_mode::none)
        {
        }
        else if (mode == client_credentials_mode::http_basic_auth)
        {
            auto unenc_auth = uri::encode_data_string(creds.username());
            unenc_auth.push_back(U(':'));
            {
                auto plaintext_secret = creds._decrypt();
                unenc_auth.append(uri::encode_data_string(*plaintext_secret));
            }
            auto utf8_unenc_auth = to_utf8string(std::move(unenc_auth));

            request.headers().add(header_names::authorization, U("Basic ")
                + _to_base64(reinterpret_cast<const unsigned char*>(utf8_unenc_auth.data()), utf8_unenc_auth.size()));
        }
        else if (mode == client_credentials_mode::request_body)
        {
            request_body.append_query(oauth2_strings::client_id, uri::encode_data_string(creds.username()), false);
            request_body.append_query(oauth2_strings::client_secret, uri::encode_data_string(*creds._decrypt()), false);
        }
        else
        {
            std::abort();
        }
    }

    pplx::task<oauth2_token> extension_grant_extract_token(
        web::uri_builder request_body,
        web::http::client::http_client token_client,
        const utility::string_t& scope,
        client_credentials_mode creds_mode)
    {
        http_request request;
        request.set_method(methods::POST);
        request.set_request_uri(utility::string_t());

        if (!scope.empty())
        {
            request_body.append_query(oauth2_strings::scope, uri::encode_data_string(scope), false);
        }

        append_client_credentials(request, request_body, token_client.client_config().credentials(), creds_mode);

        request.set_body(request_body.query(), mime_types::application_x_www_form_urlencoded);

        return token_client.request(request)
            .then([](http_response resp)
            {
                return resp.extract_json();
            }
            ).then([scope](const web::json::value& v)
            {
                return parse_token_from_json(v, scope);
            });
    }

}

pplx::task<oauth2_client> oauth2_client::create_with_auth_code_grant(
    const web::uri& auth_endpoint,
    const web::uri& local_uri,
    web::http::client::http_client token_client,
    oauth2_client::launch_user_agent_callback launch_user_agent,
    const utility::string_t& scope,
    client_credentials_mode creds_mode)
{
    auto state_cookie = utility::nonce_generator::shared_generate();

    uri_builder user_agent_base_uri(auth_endpoint);
    user_agent_base_uri.append_query(oauth2_strings::response_type, oauth2_strings::code);
    auto user_agent_url = build_authorization_uri(std::move(user_agent_base_uri), token_client.client_config().credentials().username(), local_uri.to_string(), state_cookie, scope);

    return communicate_with_user_agent(user_agent_url, local_uri, launch_user_agent)
        .then([state_cookie, scope, local_uri, token_client, creds_mode](const web::uri& redirected_uri) mutable
    {
        auto query = uri::split_query(redirected_uri.query());

        check_state_cookie(query, state_cookie);

        auto code_param = query.find(oauth2_strings::code);
        if (code_param == query.end())
        {
            throw oauth2_exception("parameter 'code' missing from redirected URI.");
        }

        uri_builder request_body_ub;
        request_body_ub.append_query(oauth2::details::oauth2_strings::grant_type, oauth2::details::oauth2_strings::authorization_code, false);
        request_body_ub.append_query(oauth2::details::oauth2_strings::code, uri::encode_data_string(code_param->second), false);
        request_body_ub.append_query(oauth2::details::oauth2_strings::redirect_uri, uri::encode_data_string(local_uri.to_string()), false);

        return create_with_extension_grant(request_body_ub, token_client, scope, creds_mode);
    });
}

pplx::task<oauth2_client> oauth2_client::create_with_implicit_grant(
    const utility::string_t& client_id,
    const web::uri& auth_endpoint,
    const web::uri& local_uri,
    launch_user_agent_callback launch_user_agent,
    const utility::string_t& scope)
{
    auto state_cookie = utility::nonce_generator::shared_generate();

    uri_builder user_agent_base_uri(auth_endpoint);
    user_agent_base_uri.append_query(oauth2_strings::response_type, oauth2_strings::token);
    auto user_agent_url = build_authorization_uri(std::move(user_agent_base_uri), client_id, local_uri.to_string(), state_cookie, scope);

    return communicate_with_user_agent(user_agent_url, local_uri, launch_user_agent)
        .then([state_cookie, scope](const web::uri& redirected_uri) mutable
    {
        auto query = uri::split_query(redirected_uri.fragment());

        check_state_cookie(query, state_cookie);

        auto token_param = query.find(oauth2_strings::access_token);
        if (token_param == query.end())
        {
            throw oauth2_exception("parameter 'access_token' missing from redirected URI.");
        }

        // Parse token from query
        oauth2_token tok(token_param->second);
        auto query_it = query.find(oauth2_strings::scope);
        if (query_it != query.end())
            tok.set_scope(query_it->second);
        else
            tok.set_scope(scope);

        query_it = query.find(oauth2_strings::expires_in);
        if (query_it != query.end())
            tok.set_expires_in(utility::details::scan_string<uint64_t>(query_it->second));
        query_it = query.find(oauth2_strings::token_type);
        if (query_it != query.end())
        {
            if (!utility::details::str_icmp(query_it->second, oauth2_strings::bearer))
            {
                throw oauth2_exception("only 'token_type=bearer' access tokens are currently supported: " + utility::conversions::to_utf8string(query_it->second));
            }
        }
        tok.set_token_type(oauth2_strings::bearer);

        return oauth2_client(tok);
    });
}

pplx::task<oauth2_client> oauth2_client::create_with_resource_owner_creds_grant(
    web::http::client::http_client token_client,
    const web::credentials& owner_credentials,
    const utility::string_t& scope,
    client_credentials_mode creds_mode)
{
    uri_builder request_body_ub;
    request_body_ub.append_query(oauth2::details::oauth2_strings::grant_type, oauth2::details::oauth2_strings::password, false);
    request_body_ub.append_query(oauth2::details::oauth2_strings::username, uri::encode_data_string(owner_credentials.username()), false);
    request_body_ub.append_query(oauth2::details::oauth2_strings::password, uri::encode_data_string(*owner_credentials._decrypt()), false);

    return create_with_extension_grant(request_body_ub, token_client, scope, creds_mode);
}

pplx::task<oauth2_client> oauth2_client::create_with_extension_grant(
    web::uri_builder request_body,
    web::http::client::http_client token_client,
    const utility::string_t& scope,
    client_credentials_mode creds_mode)
{
    return extension_grant_extract_token(request_body, token_client, scope, creds_mode)
        .then([](const oauth2_token& tok)
    {
        return oauth2_client(tok);
    });
}

pplx::task<void> oauth2_client::set_token_via_extension_grant(
    web::uri_builder request_body,
    web::http::client::http_client token_client,
    const utility::string_t& scope,
    client_credentials_mode creds_mode)
{
    auto& self = *this;
    return extension_grant_extract_token(request_body, token_client, scope, creds_mode)
        .then([self](const oauth2_token& tok)
    {
        self.m_impl->set_token(tok);
    });
}

pplx::task<void> oauth2_client::set_token_via_refresh_token(
    web::http::client::http_client token_client,
    const utility::string_t& scope,
    client_credentials_mode creds_mode)
{
    auto tok = m_impl->token();

    uri_builder request_body_ub;
    request_body_ub.append_query(oauth2::details::oauth2_strings::grant_type, oauth2::details::oauth2_strings::refresh_token, false);
    request_body_ub.append_query(oauth2::details::oauth2_strings::refresh_token, uri::encode_data_string(tok.refresh_token()), false);

    return set_token_via_extension_grant(std::move(request_body_ub), token_client, scope, creds_mode);
}

std::shared_ptr<http::http_pipeline_stage> oauth2_client::create_pipeline_stage(
    authenticated_request_mode request_mode,
    const utility::string_t& access_token_key)
{
    return std::make_shared<details::oauth2_pipeline_stage>(request_mode, access_token_key, m_impl);
}

}}}} // namespace web::http::oauth2::experimental
