using Octopus.Server.Extensibility.HostServices.Model;
using Octopus.Server.Extensibility.HostServices.Time;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public class DirectoryServicesUserSecurityGroupExpiryChecker : IDirectoryServicesUserSecurityGroupExpiryChecker
    {
        readonly IClock clock;

        public DirectoryServicesUserSecurityGroupExpiryChecker(IClock clock)
        {
            this.clock = clock;
        }

        public bool ShouldFetchExternalGroups(IUser user)
        {
            // Users groups hasn't been retrieved yet, or
            // We haven't been able to update the users groups for a week, or
            // The users groups are empty
            return !user.SecurityGroupsLastUpdated.HasValue ||
                user.SecurityGroupsLastUpdated.Value.AddDays(7) < clock.GetUtcTime() ||
                !user.HasSecurityGroupIds;
        }

        // It's been an hour since we last refreshed the users groups
        public bool ShouldFetchExternalGroupsInBackground(IUser user)
        {
            return user.SecurityGroupsLastUpdated.HasValue &&
                user.SecurityGroupsLastUpdated.Value.AddHours(1) < clock.GetUtcTime();
        }
    }
}