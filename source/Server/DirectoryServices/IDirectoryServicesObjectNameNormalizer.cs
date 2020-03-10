namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    interface IDirectoryServicesObjectNameNormalizer
    {
        void NormalizeName(string name, out string namePart, out string domainPart);

        string ValidatedUserPrincipalName(string userPrincipalName, string fallbackUsername, string fallbackDomain);
    }
}