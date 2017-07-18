using System.Security.Principal;
using Octopus.Node.Extensibility.Authentication.Extensions;
using Octopus.Node.Extensibility.Authentication.Storage.User;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Configuration;

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

        public AuthenticationUserCreateResult GetOrCreateUser(IPrincipal principal)
        {
            return !configurationStore.GetIsEnabled() ? 
                new AuthenticationUserCreateResult() : 
                credentialValidator.GetOrCreateUser(principal.Identity.Name);
        }
    }
}