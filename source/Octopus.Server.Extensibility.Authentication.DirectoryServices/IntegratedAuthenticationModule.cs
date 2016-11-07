using Nancy;
using Nancy.Responses;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;
using Octopus.Server.Extensibility.HostServices.Web;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices
{
    public class IntegratedAuthenticationModule : NancyModule
    {
        public IntegratedAuthenticationModule(IAuthCookieCreator tokenIssuer, IApiActionResponseCreator responseCreator)
        {
            Get[DirectoryServicesConstants.ChallengePath] = c =>
            {
                if (Context.CurrentUser == null)
                    return responseCreator.Unauthorized(Request);

                var principal = (IOctopusPrincipal)Context.CurrentUser;
                var tokenCookie = tokenIssuer.CreateAuthCookie(Context, principal.IdentificationToken, false);

                Response response;
                if (Request.Query["redirectTo"].HasValue && IsLocalUrl(Request.Query["redirectTo"].Value))
                {
                    var redirectLocation = Request.DirectoryPath() + "/app#" + Request.Query["redirectTo"].Value;
                    response = new RedirectResponse(redirectLocation).WithCookie(tokenCookie);
                }
                else
                {
                    response = new RedirectResponse(Request.Url.BasePath ?? "/").WithCookie(tokenCookie);
                }

                return response;
            };
        }

        public bool IsLocalUrl(string url)
        {
            // Credit to Microsoft - Preventing Open Redirection Attacks (C#)
            // http://www.asp.net/mvc/overview/security/preventing-open-redirection-attacks

            return !string.IsNullOrEmpty(url) &&

                // Allows "/" or "/foo" but not "//" or "/\".
                ((url[0] == '/' && (url.Length == 1 || (url[1] != '/' && url[1] != '\\'))) ||

                // Allows "~/" or "~/foo".
                (url.Length > 1 && url[0] == '~' && url[1] == '/'));
        }
    }
}