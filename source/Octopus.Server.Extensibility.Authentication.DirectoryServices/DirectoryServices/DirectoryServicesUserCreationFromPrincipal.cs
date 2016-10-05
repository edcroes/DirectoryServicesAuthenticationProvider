using System.Security.Principal;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Configuration;
using Octopus.Server.Extensibility.Extensions.Contracts.Authentication;
using Octopus.Server.Extensibility.HostServices.Model;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public class DirectoryServicesUserCreationFromPrincipal : ISupportsAutoUserCreationFromPrincipal
    {
        readonly IDirectoryServicesConfigurationStore configurationStore;
        readonly IDirectoryServicesCredentialValidator credentialValidator;

        public DirectoryServicesUserCreationFromPrincipal(
            IDirectoryServicesConfigurationStore configurationStore,
            IDirectoryServicesCredentialValidator credentialValidator)
        {
            this.configurationStore = configurationStore;
            this.credentialValidator = credentialValidator;
        }

        public UserCreateOrUpdateResult GetOrCreateUser(IPrincipal principal)
        {
            return !configurationStore.GetIsEnabled() ? null : credentialValidator.GetOrCreateUser(principal.Identity.Name);
        }
    }
}