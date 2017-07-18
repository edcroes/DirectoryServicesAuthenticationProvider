using System.DirectoryServices.AccountManagement;

namespace Octopus.Node.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public interface IDirectoryServicesObjectNameNormalizer
    {
        void NormalizeName(string name, out string namePart, out string domainPart);

        string ValidatedUserPrincipalName(UserPrincipal principal, string fallbackUsername, string fallbackDomain);
    }
}