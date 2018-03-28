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

                if (Request.Query["state"].HasValue)
                {
                    var stateData = HttpUtility.UrlDecode((string)Request.Query["state"].Value);
                    var state = JsonConvert.DeserializeObject<LoginState>(stateData);

                    var authCookies = tokenIssuer.CreateAuthCookies(Context.Request, principal.IdentificationToken, SessionExpiry.TwentyDays, state.UsingSecureConnection);

                    var whitelist = authenticationConfigurationStore.GetTrustedRedirectUrls();

                    if (Requests.IsLocalUrl(state.RedirectAfterLoginTo, whitelist))
                    {
                        return new RedirectResponse(state.RedirectAfterLoginTo).WithCookies(authCookies);
                    }
                    else
                    {
                        if (!string.IsNullOrWhiteSpace(state.RedirectAfterLoginTo))
                        {
                            log.WarnFormat(
                                "Prevented potential Open Redirection attack on an NTLM challenge, to the non-local url {0}",
                                state.RedirectAfterLoginTo);
                        }

                        return new RedirectResponse(Request.Url.BasePath ?? "/").WithCookies(authCookies);
                    }
                }

                return responseCreator.BadRequest("Invalid state passed to the server when setting up the NTLM challenge.");
            };
        }
    }
}