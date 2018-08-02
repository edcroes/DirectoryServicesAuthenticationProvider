using System.Net;
using Octopus.Data.Storage.Configuration;
using Octopus.Node.Extensibility.Authentication.DirectoryServices.DirectoryServices;
using Octopus.Node.Extensibility.Authentication.Extensions;
using Octopus.Node.Extensibility.Extensions.Infrastructure.Configuration;

namespace Octopus.Node.Extensibility.Authentication.DirectoryServices.Configuration
{
    public class DirectoryServicesConfigurationStore : ExtensionConfigurationStore<DirectoryServicesConfiguration>, IDirectoryServicesConfigurationStore, IAuthenticationSchemeProvider
    {
        public static string SingletonId = "authentication-directoryservices";

        public DirectoryServicesConfigurationStore(IConfigurationStore configurationStore) : base(configurationStore)
        {
        }

        public override string Id => SingletonId;

        public string ChallengePath => DirectoryServicesConstants.ChallengePath;
        public AuthenticationSchemes AuthenticationScheme => GetIsEnabled() ? GetAuthenticationScheme() : AuthenticationSchemes.Anonymous;

        public string GetActiveDirectoryContainer()
        {
            return GetProperty(doc => doc.ActiveDirectoryContainer);
        }

        public void SetActiveDirectoryContainer(string activeDirectoryContainer)
        {
            SetProperty(doc => doc.ActiveDirectoryContainer = activeDirectoryContainer);
        }

        public AuthenticationSchemes GetAuthenticationScheme()
        {
            return GetProperty(doc => doc.AuthenticationScheme);
        }

        public void SetAuthenticationScheme(AuthenticationSchemes scheme)
        {
            SetProperty(doc => doc.AuthenticationScheme = scheme);
        }

        public bool GetAllowFormsAuthenticationForDomainUsers()
        {
            return GetProperty(doc => doc.AllowFormsAuthenticationForDomainUsers);
        }

        public void SetAllowFormsAuthenticationForDomainUsers(bool allowFormAuth)
        {
            SetProperty(doc => doc.AllowFormsAuthenticationForDomainUsers = allowFormAuth);
        }

        public bool GetAreSecurityGroupsEnabled()
        {
            return GetProperty(doc => doc.AreSecurityGroupsEnabled);
        }

        public void SetAreSecurityGroupsEnabled(bool areSecurityGroupsEnabled)
        {
            SetProperty(doc => doc.AreSecurityGroupsEnabled = areSecurityGroupsEnabled);
        }
        
        public bool GetAllowAutoUserCreation()
        {
            return GetProperty(doc => doc.AllowAutoUserCreation);
        }

        public void SetAllowAutoUserCreation(bool allowAutoUserCreation)
        {
            SetProperty(doc => doc.AllowAutoUserCreation = allowAutoUserCreation);
        }
    }
}