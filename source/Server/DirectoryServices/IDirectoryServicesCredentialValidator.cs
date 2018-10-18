using System.Threading;
using Octopus.Server.Extensibility.Authentication.Extensions;
using Octopus.Server.Extensibility.Authentication.Storage.User;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public interface IDirectoryServicesCredentialValidator : IDoesBasicAuthentication
    {
        AuthenticationUserCreateResult GetOrCreateUser(string username, CancellationToken cancellationToken);
    }
}