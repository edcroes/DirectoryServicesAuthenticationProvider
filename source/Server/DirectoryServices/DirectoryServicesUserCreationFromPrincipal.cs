using System.Security.Principal;
using System.Threading;
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

        public AuthenticationUserCreateResult GetOrCreateUser(IPrincipal principal, CancellationToken cancellationToken)
        {
            return !configurationStore.GetIsEnabled() ? 
                new AuthenticationUserCreateResult() : 
                credentialValidator.GetOrCreateUser(principal.Identity.Name, cancellationToken);
        }
    }
}