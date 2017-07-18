using Octopus.Data.Model.User;

namespace Octopus.Node.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public interface IDirectoryServicesUserSecurityGroupExpiryChecker
    {
        bool ShouldFetchExternalGroups(IUser user);
        bool ShouldFetchExternalGroupsInBackground(IUser user);
    }
}