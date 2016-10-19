using Octopus.Data.Storage.User;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public interface IDirectoryServicesCredentialValidator
    {
        UserCreateOrUpdateResult ValidateCredentials(string username, string password);

        UserCreateOrUpdateResult GetOrCreateUser(string username);
    }
}