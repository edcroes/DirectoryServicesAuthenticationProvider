using System;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Configuration;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Web;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices
{
    public class DirectoryServicesApi : RegisterEndpoint
    {
        public const string ApiExternalGroupsSearch = "/api/externalgroups/directoryServices{?partialName}";
        public const string ApiExternalUsersSearch = "/api/externalusers/directoryServices{?partialName}";

        public DirectoryServicesApi(
            Func<SecuredAsyncActionInvoker<ListSecurityGroupsAction, IDirectoryServicesConfigurationStore>> listSecurityGroupsActionInvokerFactory,
            Func<SecuredAsyncActionInvoker<UserLookupAction, IDirectoryServicesConfigurationStore>> userLookupActionInvokerFactory)
        {
            Add("GET", ApiExternalGroupsSearch, listSecurityGroupsActionInvokerFactory().ExecuteAsync);
            Add("GET", ApiExternalUsersSearch, userLookupActionInvokerFactory().ExecuteAsync);
        }
    }
}