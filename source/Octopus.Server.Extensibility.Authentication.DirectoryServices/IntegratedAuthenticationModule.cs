using System.Diagnostics;
using Nancy;
using Nancy.Responses;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;
using Octopus.Server.Extensibility.HostServices.Web;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices
{
    public class IntegratedAuthenticationModule : NancyModule
    {
        readonly ILog log;

        public IntegratedAuthenticationModule(ILog log, IAuthCookieCreator tokenIssuer, IApiActionResponseCreator responseCreator)
        {
            this.log = log;

            Get[DirectoryServicesConstants.ChallengePath] = c =>
            {
                if (Context.CurrentUser == null)
                    return responseCreator.Unauthorized(Request);

                var principal = (IOctopusPrincipal)Context.CurrentUser;
                var tokenCookie = tokenIssuer.CreateAuthCookie(Context, principal.IdentificationToken, false);

                var directoryPathResult = Request.AbsoluteVirtualDirectoryPath();
                if (!directoryPathResult.IsValid)
                {
                    return responseCreator.BadRequest(directoryPathResult.InvalidReason);
                }

                string[] whitelist = null;
                if (Debugger.IsAttached)
                    whitelist = new[] { "http://localhost", "https://localhost" };

                Response response;
                if (Request.Query["redirectTo"].HasValue && Requests.IsLocalUrl(directoryPathResult.Path, Request.Query["redirectTo"].Value, whitelist))
                {
                    var redirectLocation = Request.Query["redirectTo"].Value;
                    response = new RedirectResponse(redirectLocation).WithCookie(tokenCookie);
                }
                else
                {
                    log.WarnFormat("Prevented potential Open Redirection attack on an NTLM challenge from the local instance {0} to the non-local url {1}", directoryPathResult.Path, Request.Query["redirectTo"].Value);
                    response = new RedirectResponse(directoryPathResult.Path ?? "/").WithCookie(tokenCookie);
                }

                return response;
            };
        }
    }
}