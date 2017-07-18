using System.DirectoryServices.AccountManagement;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public interface IDirectoryServicesContextProvider
    {
        PrincipalContext GetContext(string domain);
    }
}