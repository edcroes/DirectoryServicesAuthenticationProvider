using Octopus.Server.Extensibility.Authentication.Extensions;
using Octopus.Server.Extensibility.Authentication.Storage.User;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public interface IDirectoryServicesCredentialValidator : IDoesBasicAuthentication
    {
        AuthenticationUserCreateOrUpdateResult GetOrCreateUser(string username);
    }
}