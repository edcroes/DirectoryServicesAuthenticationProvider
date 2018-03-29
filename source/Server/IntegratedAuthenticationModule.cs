using System;
using Nancy;
using Nancy.Helpers;
using Nancy.Responses;
using Newtonsoft.Json;
using Octopus.Diagnostics;
using Octopus.Node.Extensibility.Authentication.DirectoryServices.DirectoryServices;
using Octopus.Node.Extensibility.Authentication.HostServices;
using Octopus.Node.Extensibility.Authentication.Resources;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices
{
    public class IntegratedAuthenticationModule : NancyModule
    {
        public IntegratedAuthenticationModule(ILog log, IAuthCookieCreator tokenIssuer, IApiActionResponseCreator responseCreator, IAuthenticationConfigurationStore authenticationConfigurationStore)
        {
            Get[DirectoryServicesConstants.ChallengePath] = c =>
            {
                if (Context.CurrentUser == null)
                    return responseCreator.Unauthorized(Request);

                var principal = (IOctopusPrincipal)Context.CurrentUser;

                // Decode the state object sent from the client (if there was one) so we can use those hints to build the most appropriate response
                // If the state can't be interpreted, we will fall back to a safe-by-default behaviour, however:
                //   1. Deep-links will not work because we don't know where the anonymous request originally wanted to go
                //   2. Cookies may not have the Secure flag set properly when SSL Offloading is in play
                LoginState state = null;
                if (Request.Query["state"].HasValue)
                {
                    try
                    {
                        var stateString = HttpUtility.UrlDecode((string) Request.Query["state"].Value);
                        state = JsonConvert.DeserializeObject<LoginState>(stateString);
                    }
                    catch (Exception e)
                    {
                        log.Warn(e, "Invalid login state object passed to the server when setting up the NTLM challenge. Falling back to the default behaviour.");
                    }
                }

                // Build the auth cookies to send back with the response
                var authCookies = tokenIssuer.CreateAuthCookies(Context.Request, principal.IdentificationToken, SessionExpiry.TwentyDays, state?.UsingSecureConnection);

                // If the caller has provided a redirect after successful login, we need to check it is a local address - preventing Open Redirection attacks
                if (!string.IsNullOrWhiteSpace(state?.RedirectAfterLoginTo))
                {
                    var whitelist = authenticationConfigurationStore.GetTrustedRedirectUrls();
                    if (Requests.IsLocalUrl(state.RedirectAfterLoginTo, whitelist))
                    {
                        // This is a safe redirect, let's go!
                        return new RedirectResponse(state.RedirectAfterLoginTo).WithCookies(authCookies);
                    }

                    // Just log that we detected a non-local redirect URL, and fall through to the root of the local web site
                    log.WarnFormat(
                        "Prevented potential Open Redirection attack on an NTLM challenge, to the non-local url {0}",
                        state.RedirectAfterLoginTo);
                }

                // By default, redirect to the root of the local web site
                return new RedirectResponse(Request.Url.BasePath ?? "/").WithCookies(authCookies);
            };
        }
    }
}