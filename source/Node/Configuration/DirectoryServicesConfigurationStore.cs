using System;
using System.Collections.Generic;
using System.Net;
using Octopus.Data.Storage.Configuration;
using Octopus.Node.Extensibility.Authentication.DirectoryServices.DirectoryServices;
using Octopus.Node.Extensibility.Authentication.Extensions;
using Octopus.Node.Extensibility.Extensions.Infrastructure.Configuration;
using Octopus.Node.Extensibility.HostServices.Mapping;

namespace Octopus.Node.Extensibility.Authentication.DirectoryServices.Configuration
{
    public class DirectoryServicesConfigurationStore : ExtensionConfigurationStore<DirectoryServicesConfiguration, DirectoryServicesConfiguration>, IDirectoryServicesConfigurationStore, IAuthenticationSchemeProvider
    {
        public static string SingletonId = "authentication-directoryservices";

        public DirectoryServicesConfigurationStore(IConfigurationStore configurationStore, IResourceMappingFactory resourceMappingfactory) : base(configurationStore, resourceMappingfactory)
        {
        }

        public string ChallengePath => DirectoryServicesConstants.ChallengePath;
        public AuthenticationSchemes AuthenticationScheme => GetIsEnabled() ? GetAuthenticationScheme() : AuthenticationSchemes.Anonymous;

        protected override DirectoryServicesConfiguration MapToResource(DirectoryServicesConfiguration doc)
        {
            return doc;
        }

        protected override DirectoryServicesConfiguration MapFromResource(DirectoryServicesConfiguration resource)
        {
            return resource;
        }

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
            return GetProperty(doc => doc.AllowAutoUserCreation.GetValueOrDefault(true));
        }

        public void SetAllowAutoUserCreation(bool allowAutoUserCreation)
        {
            SetProperty(doc => doc.AllowAutoUserCreation = allowAutoUserCreation);
        }

        public override string Id => SingletonId;

        public override string ConfigurationSetName => "Active Directory";

        public override string Description => "Active Directory authentication settings";

        public override IEnumerable<ConfigurationValue> GetConfigurationValues()
        {
            yield return new ConfigurationValue("Octopus.WebPortal.ActiveDirectoryIsEnabled", GetIsEnabled().ToString(), GetIsEnabled(), "Is Enabled");
            yield return new ConfigurationValue("Octopus.WebPortal.ActiveDirectoryContainer", GetActiveDirectoryContainer(), GetIsEnabled() && !string.IsNullOrWhiteSpace(GetActiveDirectoryContainer()), "Active Directory Container");
            yield return new ConfigurationValue("Octopus.WebPortal.AuthenticationScheme", GetAuthenticationScheme().ToString(), GetIsEnabled(), "Authentication Scheme");
            yield return new ConfigurationValue("Octopus.WebPortal.AllowFormsAuthenticationForDomainUsers", GetAllowFormsAuthenticationForDomainUsers().ToString(), GetIsEnabled(), "Allow forms authentication");
            yield return new ConfigurationValue("Octopus.WebPortal.ExternalSecurityGroupsDisabled", GetAreSecurityGroupsEnabled().ToString(), GetIsEnabled(), "Security groups enabled");
            yield return new ConfigurationValue("Octopus.WebPortal.ActiveDirectoryAllowAutoUserCreation", GetAllowAutoUserCreation().ToString(), GetIsEnabled(), "Allow auto user creation");
        }

        public override IResourceMapping GetMapping()
        {
            return ResourceMappingFactory.Create<DirectoryServicesConfigurationResource, DirectoryServicesConfiguration>();
        }
    }
}