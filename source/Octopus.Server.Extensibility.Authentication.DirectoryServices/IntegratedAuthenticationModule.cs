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

                var directoryPathResult = Request.DirectoryPath();
                if (!directoryPathResult.IsValid)
                {
                    return responseCreator.BadRequest(directoryPathResult.InvalidReason);
                }

                Response response;
                if (Request.Query["redirectTo"].HasValue && IsLocalUrl(directoryPathResult.Path, Request.Query["redirectTo"].Value))
                {
                    var redirectLocation = Request.Query["redirectTo"].Value;
                    response = new RedirectResponse(redirectLocation).WithCookie(tokenCookie);
                }
                else
                {
                    response = new RedirectResponse(directoryPathResult.Path ?? "/").WithCookie(tokenCookie);
                }

                return response;
            };
        }

        public bool IsLocalUrl(string directoryPath, string url)
        {
            // Credit to Microsoft - Preventing Open Redirection Attacks (C#)
            // http://www.asp.net/mvc/overview/security/preventing-open-redirection-attacks

            var isLocalUrl = !string.IsNullOrEmpty(url) &&
                            
                             // Allows full paths that start with the DirectoryPath
                             (url.StartsWith(directoryPath) ||

                             // Allows "/" or "/foo" but not "//" or "/\".
                             (url[0] == '/' && (url.Length == 1 || (url[1] != '/' && url[1] != '\\'))) ||

                              // Allows "~/" or "~/foo".
                              (url.Length > 1 && url[0] == '~' && url[1] == '/'));
            if (!isLocalUrl)
            {
                log.WarnFormat("Prevented potential Open Redirection attack on an NTLM challenge from the local instance {0} to the non-local url {1}", directoryPath, url);
            }

            return isLocalUrl;
        }
    }
}