using System.DirectoryServices.AccountManagement;

namespace Octopus.Node.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public interface IDirectoryServicesContextProvider
    {
        PrincipalContext GetContext(string domain);
    }
}