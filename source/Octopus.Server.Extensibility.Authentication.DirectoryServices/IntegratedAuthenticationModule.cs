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
        public IntegratedAuthenticationModule(ILog log, IAuthCookieCreator tokenIssuer, IApiActionResponseCreator responseCreator)
        {
            Get[DirectoryServicesConstants.ChallengePath] = c =>
            {
                if (Context.CurrentUser == null)
                    return responseCreator.Unauthorized(Request);

                var principal = (IOctopusPrincipal)Context.CurrentUser;
                var tokenCookie = tokenIssuer.CreateAuthCookie(Context, principal.IdentificationToken, false);

                Response response;
                if (Request.Query["redirectTo"].HasValue)
                {
                    var redirectLocation = Request.Query["redirectTo"].Value;
                    response = new RedirectResponse(redirectLocation).WithCookie(tokenCookie);
                }
                else
                {
                    response = new RedirectResponse(Request.Url.BasePath ?? "/").WithCookie(tokenCookie);
                }

                return response;
            };
        }
    }
}