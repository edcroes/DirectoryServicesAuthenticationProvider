using System;
using System.DirectoryServices.AccountManagement;
using Octopus.Node.Extensibility.Authentication.DirectoryServices.Configuration;

namespace Octopus.Node.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public class DirectoryServicesContextProvider : IDirectoryServicesContextProvider
    {
        readonly Lazy<IDirectoryServicesConfigurationStore> adConfiguration;

        public DirectoryServicesContextProvider(Lazy<IDirectoryServicesConfigurationStore> adConfiguration)
        {
            this.adConfiguration = adConfiguration;
        }

        public PrincipalContext GetContext(string domain)
        {
            var adContainer = adConfiguration.Value.GetActiveDirectoryContainer();
            adContainer = string.IsNullOrEmpty(adContainer) ? null : adContainer;

            return new PrincipalContext(ContextType.Domain, domain, adContainer);
        }
    }
}