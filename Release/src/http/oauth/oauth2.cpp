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
#define DAT(a_, b_) const oauth2_string oauth2_strings::a_(_XPLATSTR(b_));
#include "cpprest/details/http_constants.dat"
#undef _OAUTH2_STRINGS
#undef DAT

} // namespace web::http::oauth2::details

namespace experimental
{

namespace details
{
    class oauth2_client_impl : public http_pipeline_stage
    {
    private:
        mutable std::mutex m_lock;
        oauth2_token m_token;

    public:
        oauth2_client_impl(const oauth2_client_config& config) : m_config(config) {}

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

        const oauth2_client_config m_config;

        virtual pplx::task<http_response> propagate(http_request request) override
        {
            if (m_config.bearer_auth())
            {
                utility::string_t auth_hdr = _XPLATSTR("Bearer ");
                {
                    std::lock_guard<std::mutex> lock(m_lock);
                    auth_hdr += m_token.access_token();
                }
                request.headers().add(header_names::authorization, auth_hdr);
            }
            else
            {
                uri_builder ub(request.request_uri());
                utility::string_t access_token;
                {
                    std::lock_guard<std::mutex> lock(m_lock);
                    access_token = m_token.access_token();
                }
                ub.append_query(m_config.access_token_key(), access_token);
                request.set_request_uri(ub.to_uri());
            }
            return next_stage()->propagate(request);
        }

    };
}

oauth2_client::oauth2_client(const oauth2_client_config& config)
    : m_impl(std::make_shared<details::oauth2_client_impl>(config))
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

web::uri oauth2_client::redirect_uri() const
{
    return m_impl->m_config.redirect_uri();
}

web::uri oauth2_client::build_authorization_uri(grant_type grant, const utility::string_t& state_cookie) const
{
    const auto& config = m_impl->m_config;
    auto ub = config.auth_uri_builder();
    if (grant == grant_type::implicit)
        ub.append_query(oauth2_strings::response_type, oauth2_strings::token);
    else if (grant == grant_type::authorization_code)
        ub.append_query(oauth2_strings::response_type, oauth2_strings::code);
    else
        std::abort();
    ub.append_query(oauth2_strings::client_id, config._token_client().client_config().credentials().username());
    ub.append_query(oauth2_strings::redirect_uri, config.redirect_uri());

    ub.append_query(oauth2_strings::state, state_cookie);

    if (!config.scope().empty())
    {
        ub.append_query(oauth2_strings::scope, config.scope());
    }
    return ub.to_uri();
}

pplx::task<void> oauth2_client::set_token_async_from_code(const utility::string_t& authorization_code)
{
    uri_builder ub;
    ub.append_query(oauth2::details::oauth2_strings::grant_type, oauth2::details::oauth2_strings::authorization_code, false);
    ub.append_query(oauth2::details::oauth2_strings::code, uri::encode_data_string(authorization_code), false);
    ub.append_query(oauth2::details::oauth2_strings::redirect_uri, uri::encode_data_string(m_impl->m_config.redirect_uri()), false);
    return set_token_async_from_custom_request(std::move(ub));
}

pplx::task<void> oauth2_client::set_token_async_from_refresh()
{
    uri_builder ub;
    ub.append_query(oauth2::details::oauth2_strings::grant_type, oauth2::details::oauth2_strings::refresh_token, false);
    ub.append_query(oauth2::details::oauth2_strings::refresh_token, uri::encode_data_string(token().refresh_token()), false);
    return set_token_async_from_custom_request(std::move(ub));
}

pplx::task<void> oauth2_client::set_token_async_from_redirected_uri(const web::http::uri& redirected_uri, grant_type grant, const utility::string_t& state_cookie)
{
    const auto& config = m_impl->m_config;
    auto query = uri::split_query(grant == grant_type::implicit ? redirected_uri.fragment() : redirected_uri.query());

    auto state_param = query.find(oauth2_strings::state);
    if (state_param == query.end())
    {
        throw oauth2_exception("parameter 'state' missing from redirected URI.");
    }
    if (state_cookie != state_param->second)
    {
        std::ostringstream err;
        err.imbue(std::locale::classic());
        err << "redirected URI parameter 'state'='" << utility::conversions::to_utf8string(state_param->second)
            << "' does not match state='" << utility::conversions::to_utf8string(state_cookie) << "'.";
        throw oauth2_exception(err.str());
    }

    auto code_param = query.find(oauth2_strings::code);
    if (code_param != query.end())
    {
        return set_token_async_from_code(code_param->second);
    }

    // NOTE: The redirected URI contains access token only in the implicit grant.
    // The implicit grant never passes a refresh token.
    auto token_param = query.find(oauth2_strings::access_token);
    if (token_param == query.end())
    {
        throw oauth2_exception("either 'code' or 'access_token' parameter must be in the redirected URI.");
    }

    set_token(token_param->second);
    return pplx::task_from_result();
}

static oauth2_token _parse_token_from_json(const json::value& token_json, const utility::string_t& default_scope)
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
        // This however doesn't necessarily mean the token authorization scope is different.
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

pplx::task<void> oauth2_client::set_token_async_from_custom_request(uri_builder request_body_ub)
{
    const auto& config = m_impl->m_config;

    http_request request;
    request.set_method(methods::POST);
    request.set_request_uri(utility::string_t());

    if (!config.scope().empty())
    {
        request_body_ub.append_query(oauth2_strings::scope, uri::encode_data_string(config.scope()), false);
    }

    const auto& creds = config._token_client().client_config().credentials();

    if (config.auth_scheme() == auth_scheme_t::http_basic)
    {
        // Build HTTP Basic authorization header from the inner http_client_config's credentials

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
    else
    {
        // Add credentials to query as-is.
        request_body_ub.append_query(oauth2_strings::client_id, uri::encode_data_string(creds.username()), false);

        auto plaintext_secret = creds._decrypt();
        request_body_ub.append_query(oauth2_strings::client_secret, uri::encode_data_string(*plaintext_secret), false);
    }
    request.set_body(request_body_ub.query(), mime_types::application_x_www_form_urlencoded);

    return config._token_client().request(request)
    .then([](http_response resp)
    {
        return resp.extract_json();
    })
    .then([impl = m_impl](json::value json_resp) -> void
    {
        impl->set_token(_parse_token_from_json(json_resp, impl->m_config.scope()));
    });
}

std::shared_ptr<http::http_pipeline_stage> oauth2_client::create_pipeline_stage()
{
    return std::static_pointer_cast<http::http_pipeline_stage>(m_impl);
}

}}}} // namespace web::http::oauth2::experimental
