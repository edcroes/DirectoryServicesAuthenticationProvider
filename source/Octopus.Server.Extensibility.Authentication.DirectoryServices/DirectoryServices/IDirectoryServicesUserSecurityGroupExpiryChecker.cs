using Octopus.Server.Extensibility.HostServices.Model;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public interface IDirectoryServicesUserSecurityGroupExpiryChecker
    {
        bool ShouldFetchExternalGroups(IUser user);
        bool ShouldFetchExternalGroupsInBackground(IUser user);
    }
}