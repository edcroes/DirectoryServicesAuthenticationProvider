using System;
using System.Linq;
using Nancy;
using Nancy.Responses;
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

                var oau = Context.Request.Headers[ApiConstants.OctopusRequestAbsoluteUrlHeaderName]?.FirstOrDefault();
                var authCookies = tokenIssuer.CreateAuthCookies(Context.Request, principal.IdentificationToken, SessionExpiry.TwentyDays, oau);

                var whitelist = authenticationConfigurationStore.GetTrustedRedirectUrls();
                Response response;
                if (Request.Query["redirectTo"].HasValue && Requests.IsLocalUrl(Request.Query["redirectTo"].Value, whitelist))
                {
                    var redirectLocation = Request.Query["redirectTo"].Value;
                    response = new RedirectResponse(redirectLocation).WithCookies(authCookies);
                }
                else
                {
                    if (Request.Query["redirectTo"].HasValue)
                    {
                        log.WarnFormat("Prevented potential Open Redirection attack on an NTLM challenge, to the non-local url {0}", Request.Query["redirectTo"].Value);
                    }

                    response = new RedirectResponse(Request.Url.BasePath ?? "/").WithCookies(authCookies);
                }

                return response;
            };
        }
    }
}