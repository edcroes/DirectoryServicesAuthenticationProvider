using Octopus.Data.Model.User;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public interface IDirectoryServicesUserSecurityGroupExpiryChecker
    {
        bool ShouldFetchExternalGroups(ActiveDirectoryIdentity identity);
        bool ShouldFetchExternalGroupsInBackground(ActiveDirectoryIdentity identity);
    }
}