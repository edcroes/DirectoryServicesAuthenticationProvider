using System;
using Nancy;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Configuration;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Web;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices
{
    public class DirectoryServicesApi : NancyModule
    {
        public const string ApiExternalGroupsLookup = "/api/externalgroups/directoryServices{?partialName}";
        public const string ApiExternalUsersLookup = "/api/externalusers/directoryServices{?partialName}";

        public DirectoryServicesApi(
            Func<SecuredActionInvoker<ListSecurityGroupsAction, IDirectoryServicesConfigurationStore>> listSecurityGroupsActionInvokerFactory,
            Func<SecuredActionInvoker<UserLookupAction, IDirectoryServicesConfigurationStore>> userLookupActionInvokerFactory)
        {
            Get[ApiExternalGroupsLookup] = o => listSecurityGroupsActionInvokerFactory().Execute(Context, Response);
            Get[ApiExternalUsersLookup] = o => userLookupActionInvokerFactory().Execute(Context, Response);
        }
    }
}