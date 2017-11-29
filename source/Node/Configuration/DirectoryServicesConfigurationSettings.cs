using System.Collections.Generic;
using Octopus.Node.Extensibility.Extensions.Infrastructure.Configuration;
using Octopus.Node.Extensibility.HostServices.Mapping;

namespace Octopus.Node.Extensibility.Authentication.DirectoryServices.Configuration
{
    public class DirectoryServicesConfigurationSettings :
        ExtensionConfigurationSettings<DirectoryServicesConfiguration, DirectoryServicesConfigurationResource,
            IDirectoryServicesConfigurationStore>, IDirectoryServicesConfigurationSettings
    {
        public DirectoryServicesConfigurationSettings(
            IDirectoryServicesConfigurationStore configurationDocumentStore,
            IResourceMappingFactory factory) : base(configurationDocumentStore, factory)
        {
        }

        public override string Id => DirectoryServicesConfigurationStore.SingletonId;

        public override string ConfigurationSetName => "Active Directory";

        public override string Description => "Active Directory authentication settings";

        public override IEnumerable<ConfigurationValue> GetConfigurationValues()
        {
            var isEnabled = ConfigurationDocumentStore.GetIsEnabled();

            yield return new ConfigurationValue("Octopus.WebPortal.ActiveDirectoryIsEnabled", isEnabled.ToString(), isEnabled, "Is Enabled");
            yield return new ConfigurationValue("Octopus.WebPortal.ActiveDirectoryContainer", ConfigurationDocumentStore.GetActiveDirectoryContainer(), isEnabled && !string.IsNullOrWhiteSpace(ConfigurationDocumentStore.GetActiveDirectoryContainer()), "Active Directory Container");
            yield return new ConfigurationValue("Octopus.WebPortal.AuthenticationScheme", ConfigurationDocumentStore.GetAuthenticationScheme().ToString(), isEnabled, "Authentication Scheme");
            yield return new ConfigurationValue("Octopus.WebPortal.AllowFormsAuthenticationForDomainUsers", ConfigurationDocumentStore.GetAllowFormsAuthenticationForDomainUsers().ToString(), isEnabled, "Allow forms authentication");
            yield return new ConfigurationValue("Octopus.WebPortal.ExternalSecurityGroupsDisabled", ConfigurationDocumentStore.GetAreSecurityGroupsEnabled().ToString(), isEnabled, "Security groups enabled");
            yield return new ConfigurationValue("Octopus.WebPortal.ActiveDirectoryAllowAutoUserCreation", ConfigurationDocumentStore.GetAllowAutoUserCreation().ToString(), isEnabled, "Allow auto user creation");
        }

        public override IEnumerable<IResourceMapping> GetMappings()
        {
            return new[] { ResourceMappingFactory.Create<DirectoryServicesConfigurationResource, DirectoryServicesConfiguration>() };
        }
    }
}