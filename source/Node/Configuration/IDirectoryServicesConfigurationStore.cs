using System.Net;
using Octopus.Node.Extensibility.Extensions.Infrastructure.Configuration;

namespace Octopus.Node.Extensibility.Authentication.DirectoryServices.Configuration
{
    public interface IDirectoryServicesConfigurationStore : IExtensionConfigurationStore
    {
        string GetActiveDirectoryContainer();
        void SetActiveDirectoryContainer(string activeDirectoryContainer);

        AuthenticationSchemes GetAuthenticationScheme();
        void SetAuthenticationScheme(AuthenticationSchemes scheme);

        bool GetAllowFormsAuthenticationForDomainUsers();
        void SetAllowFormsAuthenticationForDomainUsers(bool allowFormAuth);

        bool GetAreSecurityGroupsEnabled();
        void SetAreSecurityGroupsEnabled(bool areSecurityGroupsEnabled);

        bool GetAllowAutoUserCreation();
        void SetAllowAutoUserCreation(bool allowAutoUserCreation);
    }
}