using System;
using Nancy;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Configuration;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Web;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices
{
    public class DirectoryServicesApi : NancyModule
    {
        public const string ApiUsersAuthenticate = "/api/users/authenticate/directoryServices";
        public const string ApiExternalGroupsLookup = "/api/externalgroups/directoryServices{?name}";

        public DirectoryServicesApi(
            Func<WhenEnabledActionInvoker<UserLoginAction, IDirectoryServicesConfigurationStore>> userLoginActionInvokerFactory,
            Func<SecuredActionInvoker<ListSecurityGroupsAction, IDirectoryServicesConfigurationStore>> listSecurityGroupsActionInvokerFactory)
        {
            Post[ApiUsersAuthenticate] = o => userLoginActionInvokerFactory().Execute(Context, Response);

            Get[ApiExternalGroupsLookup] = o => listSecurityGroupsActionInvokerFactory().Execute(Context, Response);
        }
    }
}