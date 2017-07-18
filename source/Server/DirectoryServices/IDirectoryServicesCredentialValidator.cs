using Octopus.Node.Extensibility.Authentication.Extensions;
using Octopus.Node.Extensibility.Authentication.Storage.User;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public interface IDirectoryServicesCredentialValidator : IDoesBasicAuthentication
    {
        AuthenticationUserCreateResult GetOrCreateUser(string username);
    }
}