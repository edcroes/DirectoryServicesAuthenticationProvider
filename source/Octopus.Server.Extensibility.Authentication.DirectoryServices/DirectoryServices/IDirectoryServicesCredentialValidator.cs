using Octopus.Server.Extensibility.HostServices.Model;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public interface IDirectoryServicesCredentialValidator
    {
        UserCreateOrUpdateResult ValidateCredentials(string username, string password);

        UserCreateOrUpdateResult GetOrCreateUser(string username);
    }
}