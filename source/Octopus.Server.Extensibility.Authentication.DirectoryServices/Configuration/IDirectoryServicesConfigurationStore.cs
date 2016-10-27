using System.Net;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.Configuration
{
    public interface IDirectoryServicesConfigurationStore : IExtensionConfigurationStore
    {
        string GetActiveDirectoryContainer();
        void SetActiveDirectoryContainer(string activeDirectoryContainer);

        AuthenticationSchemes GetAuthenticationScheme();
        void SetAuthenticationScheme(AuthenticationSchemes scheme);

        bool GetAllowFormsAuthenticationForDomainUsers();
        void SetAllowFormsAuthenticationForDomainUsers(bool allowFormAuth);

        bool GetAreSecurityGroupsDisabled();
        void SetAreSecurityGroupsDisabled(bool allowFormAuth);
    }
}