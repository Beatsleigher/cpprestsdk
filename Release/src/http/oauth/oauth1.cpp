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
* HTTP Library: Oauth 1.0
*
* For the latest on this and related APIs, please see: https://github.com/Microsoft/cpprestsdk
*
* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
****/

#include "stdafx.h"
#include "cpprest/oauth1.h"
#if !defined(CPPREST_TARGET_XP)

using namespace utility;
using web::http::client::http_client;
using web::http::client::http_client_config;
using web::http::oauth1::details::oauth1_state;
using web::http::oauth1::details::oauth1_strings;

namespace web { namespace http { namespace oauth1
{

namespace details
{

#define _OAUTH1_STRINGS
#define DAT(a_, b_) const oauth1_string oauth1_strings::a_(_XPLATSTR(b_));
#include "cpprest/details/http_constants.dat"
#undef _OAUTH1_STRINGS
#undef DAT

} // namespace web::http::oauth1::details

namespace experimental
{

//
// Start of platform-dependent _hmac_sha1() block...
//
#if defined(_WIN32) && !defined(__cplusplus_winrt) // Windows desktop

#include <winternl.h>
#include <bcrypt.h>

// Code analysis complains even though there is no bug.
#pragma warning(push)
#pragma warning(disable : 6102)
static std::vector<unsigned char> _hmac_sha1(const utility::string_t& key, const utility::string_t& data)
{
    NTSTATUS status;
    BCRYPT_ALG_HANDLE alg_handle = nullptr;
    BCRYPT_HASH_HANDLE hash_handle = nullptr;

    std::vector<unsigned char> hash;
    DWORD hash_len = 0;
    ULONG result_len = 0;

    const auto &key_c = conversions::utf16_to_utf8(key);
    const auto &data_c = conversions::utf16_to_utf8(data);

    status = BCryptOpenAlgorithmProvider(&alg_handle, BCRYPT_SHA1_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }
    status = BCryptGetProperty(alg_handle, BCRYPT_HASH_LENGTH, (PBYTE) &hash_len, sizeof(hash_len), &result_len, 0);
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }
    hash.resize(hash_len);

    status = BCryptCreateHash(alg_handle, &hash_handle, nullptr, 0, (PBYTE) key_c.c_str(), (ULONG) key_c.length(), 0);
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }
    status = BCryptHashData(hash_handle, (PBYTE) data_c.c_str(), (ULONG) data_c.length(), 0);
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }
    status = BCryptFinishHash(hash_handle, hash.data(), hash_len, 0);
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

cleanup:
    if (hash_handle)
    {
        BCryptDestroyHash(hash_handle);
    }
    if (alg_handle)
    {
        BCryptCloseAlgorithmProvider(alg_handle, 0);
    }

    return hash;
}
#pragma warning(pop)

#elif defined(_WIN32) && defined(__cplusplus_winrt) // Windows RT

using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;

static std::vector<unsigned char> _hmac_sha1(const utility::string_t& key, const utility::string_t& data)
{
    Platform::String^ data_str = ref new Platform::String(data.c_str());
    Platform::String^ key_str = ref new Platform::String(key.c_str());

    MacAlgorithmProvider^ HMACSha1Provider = MacAlgorithmProvider::OpenAlgorithm(MacAlgorithmNames::HmacSha1);
    IBuffer^ content_buffer = CryptographicBuffer::ConvertStringToBinary(data_str, BinaryStringEncoding::Utf8);
    IBuffer^ key_buffer = CryptographicBuffer::ConvertStringToBinary(key_str, BinaryStringEncoding::Utf8);

    auto signature_key = HMACSha1Provider->CreateKey(key_buffer);
    auto signed_buffer = CryptographicEngine::Sign(signature_key, content_buffer);

    Platform::Array<unsigned char, 1>^ arr;
    CryptographicBuffer::CopyToByteArray(signed_buffer, &arr);
    return std::vector<unsigned char>(arr->Data, arr->Data + arr->Length);
}

#else // Linux, Mac OS X

#include <openssl/hmac.h>

static std::vector<unsigned char> _hmac_sha1(const utility::string_t& key, const utility::string_t& data)
{
    unsigned char digest[HMAC_MAX_MD_CBLOCK];
    unsigned int digest_len = 0;

    HMAC(EVP_sha1(), key.c_str(), static_cast<int>(key.length()),
            (const unsigned char*) data.c_str(), data.length(),
            digest, &digest_len);

    return std::vector<unsigned char>(digest, digest + digest_len);
}

#endif
//
// ...End of platform-dependent _hmac_sha1() block.
//

// Notes:
// - Doesn't support URIs without scheme or host.
// - If URI port is unspecified.
static utility::string_t build_base_string_uri(const uri& u)
{
    utility::ostringstream_t os;
    os.imbue(std::locale::classic());
    os << u.scheme() << "://" << u.host();
    if (!u.is_port_default() && u.port() != 80 && u.port() != 443)
    {
        os << ":" << u.port();
    }
    os << u.path();
    return uri::encode_data_string(os.str());
}

static void normalize_query_map(std::vector<utility::string_t>& v, const std::map<utility::string_t, utility::string_t>& map)
{
    for (const auto& query : map)
    {
        utility::string_t s;
        s.reserve(query.first.size() + 1 + query.second.size());
        s.append(query.first);
        s.push_back(_XPLATSTR('='));
        s.append(query.second);
        v.push_back(std::move(s));
    }
};

static void normalize_parameters_from_config(std::vector<utility::string_t>& v, const oauth1_config& config)
{
    normalize_query_map(v, config.parameters());

    v.push_back(oauth1_strings::consumer_key + U("=") + web::uri::encode_data_string(config.consumer_key()));
    if (!config.token().access_token().empty())
    {
        v.push_back(oauth1_strings::token + U("=") + web::uri::encode_data_string(config.token().access_token()));
    }
    v.push_back(oauth1_strings::signature_method + U("=") + config.method());
}
static void normalize_state_parameters(std::vector<utility::string_t>& v, const oauth1_state& state)
{
    v.push_back(oauth1_strings::timestamp + U("=") + state.timestamp());
    v.push_back(oauth1_strings::nonce + U("=") + state.nonce());
    if (!state.extra_key().empty())
    {
        v.push_back(state.extra_key() + U("=") + web::uri::encode_data_string(state.extra_value()));
    }
}

/// <summary>
/// Sorts parameters and concatenates every entry, interspersing ampersands.
/// </summary>
/// <example>
/// <code>
/// flatten_normalize_parameters({ "a=1", "c=2", "b=3" }) == "a=1&b=3&c=2"
/// </code>
/// </example>
static utility::string_t flatten_normalized_parameters(std::vector<utility::string_t>& parameters)
{
    sort(parameters.begin(), parameters.end());

    utility::string_t out_string;
    // The output string will have every entry from the parameter list, separated with '&'s.
    assert(parameters.size() > 0);
    size_t total_length = parameters.size() - 1;
    for (auto&& p : parameters)
        total_length += p.size();

    out_string.reserve(total_length);

    out_string.append(parameters.front());

    auto b = parameters.begin() + 1;
    auto e = parameters.end();
    for (; b != e; ++b)
    {
        out_string.push_back(_XPLATSTR('&'));
        out_string.append(*b);
    }
    return out_string;
}

static bool is_application_x_www_form_urlencoded(const http_request &request)
{
    const auto& urlenc_mime = web::http::details::mime_types::application_x_www_form_urlencoded;

    auto it = request.headers().find(header_names::content_type);
    if (it != request.headers().end())
    {
        // compare if content_type begins with application_x_www_form_urlencoded, since it is often suffixed with "; charset=utf-8"
        if (wcsncmp(it->second.c_str(), urlenc_mime.c_str(), urlenc_mime.size()) == 0)
            return true;
    }
    return false;
}

// Builds signature base string according to:
// http://tools.ietf.org/html/rfc5849#section-3.4.1.1
static utility::string_t _build_signature_base_string(
    const oauth1_config& config,
    const web::http::method& http_method,
    const web::uri& http_uri,
    const utility::string_t& urlencoded_body,
    const oauth1_state& state)
{
    utility::ostringstream_t os;
    os.imbue(std::locale::classic());
    os << http_method;
    os << "&" << build_base_string_uri(http_uri);

    auto query_string = http_uri.query();

    // http://oauth.net/core/1.0a/#signing_process
    // 9.1.1.  Normalize Request Parameters
    // The request parameters are collected, sorted and concatenated into a normalized string:
    //	- Parameters in the OAuth HTTP Authorization header excluding the realm parameter.
    //	- Parameters in the HTTP POST request body (with a content-type of application/x-www-form-urlencoded).
    //	- HTTP GET parameters added to the URLs in the query part (as defined by [RFC3986] section 3).
    if (!urlencoded_body.empty())
    {
        if (!query_string.empty() && query_string.back() != _XPLATSTR('&'))
        {
            query_string.push_back(_XPLATSTR('&'));
        }
        query_string.append(urlencoded_body);
    }

    std::vector<utility::string_t> queries;

    normalize_query_map(queries, uri::split_query(query_string));
    normalize_parameters_from_config(queries, config);
    normalize_state_parameters(queries, state);

    queries.push_back(oauth1_strings::version + U("=1.0"));

    os << "&" << uri::encode_data_string(flatten_normalized_parameters(queries));

    return os.str();
}

static utility::string_t _build_encoded_plaintext_signature(const oauth1_config& config)
{
    return uri::encode_data_string(config.consumer_secret()) + _XPLATSTR("&") + uri::encode_data_string(config.token().secret());
}

static utility::string_t build_authorization_header(
    const oauth1_config& config,
    const web::http::method& http_method,
    const web::uri& http_uri,
    const utility::string_t& urlencoded_body,
    const oauth1_state& state)
{
    utility::ostringstream_t os;
    os.imbue(std::locale::classic());
    os << "OAuth ";
    if (!config.realm().empty())
    {
        os << oauth1_strings::realm << "=\"" << web::uri::encode_data_string(config.realm()) << "\", ";
    }
    os << oauth1_strings::version << "=\"1.0";
    os << "\", " << oauth1_strings::consumer_key << "=\"" << web::uri::encode_data_string(config.consumer_key());
    if (!config.token().access_token().empty())
    {
        os << "\", " << oauth1_strings::token << "=\"" << web::uri::encode_data_string(config.token().access_token());
    }
    os << "\", " << oauth1_strings::signature_method << "=\"" << method();
    os << "\", " << oauth1_strings::timestamp << "=\"" << state.timestamp();
    os << "\", " << oauth1_strings::nonce << "=\"" << state.nonce();
    if (!state.extra_key().empty())
    {
        os << ", " << state.extra_key() << "=\"" << web::uri::encode_data_string(state.extra_value()) << "\"";
    }

    auto plaintext_signature = _build_encoded_plaintext_signature(config);

    if (method() == oauth1_methods::hmac_sha1)
    {
        // Builds HMAC-SHA1 signature according to:
        // http://tools.ietf.org/html/rfc5849#section-3.4.2
        auto digest = _hmac_sha1(plaintext_signature,
            _build_signature_base_string(config, http_method, http_uri, urlencoded_body, state));
        os << "\", " << oauth1_strings::signature << "=\""
            << utility::conversions::to_base64(std::move(digest));
    }
    else if (method() == oauth1_methods::plaintext)
    {
        os << "\", " << oauth1_strings::signature << "=\"" << plaintext_signature;
    }
    else
    {
        // Programmer error or data corruption, fail fast
        std::abort();
    }
    os << "\"";

    return os.str();
}

pplx::task<void> oauth1_config::_request_token(oauth1_state state, bool is_temp_token_request)
{
    utility::string_t endpoint = is_temp_token_request ? temp_endpoint() : token_endpoint();
    http_request req;
    req.set_method(methods::POST);
    req.set_request_uri(utility::string_t());

    {
        web::uri endpoint_uri = endpoint;

        req._set_base_uri(endpoint_uri);

        req.headers().add(header_names::authorization,
            build_authorization_header(*this, methods::POST, endpoint_uri, _XPLATSTR(""), state));
    }


    // configure proxy
    http_client_config config;
    config.set_proxy(m_proxy);

    http_client client(endpoint, config);

    return client.request(req)
        .then([](http_response resp)
    {
        return resp.extract_string();
    })
        .then([this, is_temp_token_request](utility::string_t body) -> void
    {
        auto query(uri::split_query(body));

        if (is_temp_token_request)
        {
            auto callback_confirmed_param = query.find(oauth1_strings::callback_confirmed);
            if (callback_confirmed_param == query.end())
            {
                throw oauth1_exception(U("parameter 'oauth_callback_confirmed' is missing from response: ") + body
                    + U(". the service may be using obsoleted and insecure OAuth Core 1.0 protocol."));
            }
        }

        auto token_param = query.find(oauth1_strings::token);
        if (token_param == query.end())
        {
            throw oauth1_exception(U("parameter 'oauth_token' missing from response: ") + body);
        }

        auto token_secret_param = query.find(oauth1_strings::token_secret);
        if (token_secret_param == query.end())
        {
            throw oauth1_exception(U("parameter 'oauth_token_secret' missing from response: ") + body);
        }

        // Here the token can be either temporary or access token.
        // The authorization is complete if it is access token.
        m_is_authorization_completed = !is_temp_token_request;
        m_token = oauth1_token(web::uri::decode(token_param->second), web::uri::decode(token_secret_param->second));

        for (const auto& qa : query)
        {
            if (qa.first == oauth1_strings::token || qa.first == oauth1_strings::token_secret) continue;
            m_token.set_additional_parameter(web::uri::decode(qa.first), web::uri::decode(qa.second));
        }
    });
}

pplx::task<utility::string_t> oauth1_config::build_authorization_uri()
{
    pplx::task<void> temp_token_req = _request_token(_generate_auth_state(oauth1_strings::callback, callback_uri()), true);

    return temp_token_req.then([this]
    {
        uri_builder ub(auth_endpoint());
        ub.append_query(oauth1_strings::token, m_token.access_token());
        return ub.to_string();
    });
}

pplx::task<void> oauth1_config::token_from_redirected_uri(const web::http::uri& redirected_uri)
{
    auto query = uri::split_query(redirected_uri.query());

    auto token_param = query.find(oauth1_strings::token);
    if (token_param == query.end())
    {
        return pplx::task_from_exception<void>(oauth1_exception(U("parameter 'oauth_token' missing from redirected URI.")));
    }
    if (m_token.access_token() != token_param->second)
    {
        utility::ostringstream_t err;
        err.imbue(std::locale::classic());
        err << U("redirected URI parameter 'oauth_token'='") << token_param->second
            << U("' does not match temporary token='") << m_token.access_token() << U("'.");
        return pplx::task_from_exception<void>(oauth1_exception(err.str().c_str()));
    }

    auto verifier_param = query.find(oauth1_strings::verifier);
    if (verifier_param == query.end())
    {
        return pplx::task_from_exception<void>(oauth1_exception(U("parameter 'oauth_verifier' missing from redirected URI.")));
    }

    return token_from_verifier(verifier_param->second);
}

// Remove once VS 2013 is no longer supported.
#if defined(_WIN32) && _MSC_VER < 1900
static const oauth1_token empty_token;
#endif
const oauth1_token& oauth1_config::token() const
{
    if (m_is_authorization_completed)
    {
        // Return the token object only if authorization has been completed.
        // Otherwise the token object holds a temporary token which should not be
        // returned to the user.
        return m_token;
    }
    else
    {
#if !defined(_WIN32) || _MSC_VER >= 1900
        static const oauth1_token empty_token;
#endif
        return empty_token;
    }
}

#define _OAUTH1_METHODS
#define DAT(a,b) const oauth1_method oauth1_methods::a = b;
#include "cpprest/details/http_constants.dat"
#undef _OAUTH1_METHODS
#undef DAT

namespace details
{
    class oauth1_pipeline_stage : public http_pipeline_stage
    {
    public:
        oauth1_pipeline_stage(const experimental::oauth1_config& cfg) :
            m_config(cfg)
        {}

        virtual pplx::task<http_response> propagate(http_request request) override
        {
            utility::string_t urlencoded_body;
            if (is_application_x_www_form_urlencoded(request))
            {
                // Note: this should be improved to not block and handle any potential exceptions.
                urlencoded_body = request.extract_string(true).get();
                request.set_body(urlencoded_body, web::http::details::mime_types::application_x_www_form_urlencoded);
            }

            auto auth_header = build_authorization_header(
                m_config,
                request.method(),
                request.absolute_uri(),
                urlencoded_body,
                m_config._generate_auth_state());
            request.headers().add(header_names::authorization, std::move(auth_header));
            return next_stage()->propagate(request);
        }

    private:
        experimental::oauth1_config m_config;
    };

}

std::shared_ptr<http::http_pipeline_stage> oauth1_config::create_pipeline_stage() const
{
    return std::static_pointer_cast<http::http_pipeline_stage>(std::make_shared<details::oauth1_pipeline_stage>(*this));
}

}}}}

#endif
