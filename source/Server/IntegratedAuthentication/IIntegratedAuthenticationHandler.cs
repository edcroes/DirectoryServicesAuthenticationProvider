using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.IntegratedAuthentication
{
    interface IIntegratedAuthenticationHandler
    {
        Task HandleRequest(HttpContext context);
    }
}