using System.Threading;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public interface IDirectoryServicesService
    {
        UserValidationResult ValidateCredentials(string username, string password, CancellationToken cancellationToken);
        UserValidationResult FindByIdentity(string username);
    }
}