using Microsoft.AspNetCore.Http;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.IntegratedAuthentication
{
    interface IIntegratedAuthenticationHandler
    {
        void HandleRequest(HttpContext context);
    }
}