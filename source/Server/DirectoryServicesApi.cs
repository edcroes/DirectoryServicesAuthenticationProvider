using System;
using Nancy;
using Octopus.Node.Extensibility.Authentication.DirectoryServices.Configuration;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Web;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices
{
    public class DirectoryServicesApi : NancyModule
    {
        public const string ApiExternalGroupsLookup = "/api/externalgroups/directoryServices{?name}";

        public DirectoryServicesApi(
            Func<SecuredActionInvoker<ListSecurityGroupsAction, IDirectoryServicesConfigurationStore>> listSecurityGroupsActionInvokerFactory)
        {
            Get[ApiExternalGroupsLookup] = o => listSecurityGroupsActionInvokerFactory().Execute(Context, Response);
        }
    }
}