using System.Security.Principal;
using Octopus.Data.Storage.User;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Configuration;
using Octopus.Server.Extensibility.Authentication.Extensions;
using Octopus.Server.Extensibility.Authentication.Storage.User;

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

        public AuthenticationUserCreateOrUpdateResult GetOrCreateUser(IPrincipal principal)
        {
            return !configurationStore.GetIsEnabled() ? 
                new AuthenticationUserCreateOrUpdateResult() : 
                credentialValidator.GetOrCreateUser(principal.Identity.Name);
        }
    }
}