using System.DirectoryServices.AccountManagement;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public interface IDirectoryServicesCredentialNormalizer
    {
        void NormalizeCredentials(string username, out string usernamePart, out string domainPart);

        string ValidatedUserPrincipalName(UserPrincipal principal, string fallbackUsername, string fallbackDomain);
    }
}