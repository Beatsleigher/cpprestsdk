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
* Oauth2Client.cpp : Defines the entry point for the console application
*
* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
****/

/*

INSTRUCTIONS

This sample performs authorization code grant flow on various OAuth 2.0
services and then requests basic user information.

This sample is for Windows Desktop, OS X and Linux.
Execute with administrator privileges.

Set the app key & secret strings below (i.e. s_dropbox_key, s_dropbox_secret, etc.)
To get key & secret, register an app in the corresponding service.

Set following entry in the hosts file:
127.0.0.1    testhost.local

*/
#include "stdafx.h"

#if defined(_WIN32) && !defined(__cplusplus_winrt)
// Extra includes for Windows desktop.
#include <windows.h>
#include <Shellapi.h>
#endif

#include "cpprest/http_listener.h"
#include "cpprest/http_client.h"
#include "cpprest/oauth2.h"

using namespace utility;
using namespace web;
using namespace web::http;
using namespace web::http::client;
using namespace web::http::oauth2::experimental;
using namespace web::http::experimental::listener;

//
// Set key & secret pair to enable session for that service.
//
static const utility::string_t s_dropbox_key(U(""));
static const utility::string_t s_dropbox_secret(U(""));

static const utility::string_t s_linkedin_key(U(""));
static const utility::string_t s_linkedin_secret(U(""));

static const utility::string_t s_live_key(U(""));
static const utility::string_t s_live_secret(U(""));

//
// Utility method to open browser on Windows, OS X and Linux systems.
//
static void open_browser(utility::string_t auth_uri)
{
#if defined(_WIN32) && !defined(__cplusplus_winrt)
    // NOTE: Windows desktop only.
    auto r = ShellExecuteA(NULL, "open", conversions::utf16_to_utf8(auth_uri).c_str(), NULL, NULL, SW_SHOWNORMAL);
#elif defined(__APPLE__)
    // NOTE: OS X only.
    string_t browser_cmd(U("open \"") + auth_uri + U("\""));
    system(browser_cmd.c_str());
#else
    // NOTE: Linux/X11 only.
    string_t browser_cmd(U("xdg-open \"") + auth_uri + U("\""));
    system(browser_cmd.c_str());
#endif
}

class oauth2_authorization_client
{
public:
    oauth2_authorization_client(const oauth2_client& client)
        : m_client(client)
    {}

    oauth2_client m_client;

    void authorization_code_flow()
    {
        if (m_client.token().is_valid_access_token())
            return;

        auto state_cookie = nonce_generator::shared_generate();

        pplx::task_completion_event<void> m_tce;

        http_listener m_listener(m_client.redirect_uri());
        m_listener.support([this, m_tce, &state_cookie](http::http_request request) -> void
        {
            if (request.request_uri().path() == U("/") && request.request_uri().query() != U(""))
            {
                m_client.set_token_async_from_redirected_uri(request.request_uri(), state_cookie)
                    .then([m_tce](pplx::task<void> token_task) -> void
                {
                    try
                    {
                        token_task.wait();
                        m_tce.set();
                    }
                    catch (...)
                    {
                        m_tce.set_exception(std::current_exception());
                    }
                });

                request.reply(status_codes::OK, U("Ok."));
            }
            else
            {
                m_tce.set_exception(std::runtime_error("Bad http request received"));
                request.reply(status_codes::NotFound, U("Not found."));
            }
        });
        m_listener.open().wait();

        auto auth_uri = m_client.build_authorization_uri(state_cookie);

        ucout << "Opening browser in URI:" << std::endl;
        ucout << auth_uri.to_string() << std::endl;

        open_browser(auth_uri.to_string());

        pplx::create_task(m_tce).wait();
        m_listener.close().wait();
    }
};

//
// Specialized class for Dropbox OAuth 2.0 session.
//
class dropbox_session_sample
{
public:
    dropbox_session_sample() :
        oauth2_session_sample(U("Dropbox"),
            oauth2_config(s_dropbox_key,
                s_dropbox_secret,
                U("https://www.dropbox.com/1/oauth2/authorize"),
                U("https://api.dropbox.com/1/oauth2/token"),
                U("http://localhost:8889/")))
    {
        // Dropbox uses "default" OAuth 2.0 settings.
    }

    void run()
    {

    }

protected:
    void run_internal() override
    {
        http_client api(U("https://api.dropbox.com/1/"));
        api.add_handler(m_client.create_pipeline_stage());

        ucout << "Requesting account information:" << std::endl;
        ucout << "Information: " << api.request(methods::GET, U("account/info")).get().extract_json().get() << std::endl;
    }
};

//
// Specialized class for LinkedIn OAuth 2.0 session.
//
class linkedin_session_sample
{
public:
    static linkedin_session_sample construct()
    {
        oauth2_config linkedin_config(
            s_linkedin_key,
            s_linkedin_secret,
            U("https://www.linkedin.com/uas/oauth2/authorization"),
            U("https://www.linkedin.com/uas/oauth2/accessToken"),
            U("http://localhost:8888/");

    }
    linkedin_session_sample() :
        oauth2_session_sample(U("LinkedIn"))
    {
        // LinkedIn doesn't use bearer auth.
        m_oauth2_config.set_bearer_auth(false);
        // Also doesn't use HTTP Basic for token endpoint authentication.
        m_oauth2_config.set_http_basic_auth(false);
        // Also doesn't use the common "access_token", but "oauth2_access_token".
        m_oauth2_config.set_access_token_key(U("oauth2_access_token"));
    }

protected:
    void run_internal() override
    {
        http_client api(U("https://api.linkedin.com/v1/people/"), m_http_config);
        ucout << "Requesting account information:" << std::endl;
        ucout << "Information: " << api.request(methods::GET, U("~?format=json")).get().extract_json().get() << std::endl;
    }

};

//
// Specialized class for Microsoft Live Connect OAuth 2.0 session.
//
class live_session_sample : public oauth2_session_sample
{
public:
    live_session_sample() :
        oauth2_session_sample(U("Live"),
            s_live_key,
            s_live_secret,
            U("https://login.live.com/oauth20_authorize.srf"),
            U("https://login.live.com/oauth20_token.srf"),
            U("http://testhost.local:8890/"))
    {
        // Scope "wl.basic" allows fetching user information.
        m_oauth2_config.set_scope(U("wl.basic"));
    }

protected:
    void run_internal() override
    {
        http_client api(U("https://apis.live.net/v5.0/"), m_http_config);
        ucout << "Requesting account information:" << std::endl;
        ucout << api.request(methods::GET, U("me")).get().extract_json().get() << std::endl;
    }
};


#ifdef _WIN32
int wmain(int argc, wchar_t *argv[])
#else
int main(int argc, char *argv[])
#endif
{
    ucout << "Running OAuth 2.0 client sample..." << std::endl;

    linkedin_session_sample linkedin;
    dropbox_session_sample  dropbox;
    live_session_sample     live;

    linkedin.run();
    dropbox.run();
    live.run();

    ucout << "Done." << std::endl;
    return 0;
}
