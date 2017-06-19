using System.Linq;
using Octopus.Data.Model.User;
using Octopus.Time;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public class DirectoryServicesUserSecurityGroupExpiryChecker : IDirectoryServicesUserSecurityGroupExpiryChecker
    {
        readonly IClock clock;

        public DirectoryServicesUserSecurityGroupExpiryChecker(IClock clock)
        {
            this.clock = clock;
        }

        public bool ShouldFetchExternalGroups(ActiveDirectoryIdentity identity)
        {
            // Users groups hasn't been retrieved yet, or
            // We haven't been able to update the users groups for a week, or
            // The users groups are empty
            return !identity.SecurityGroupsLastUpdated.HasValue ||
                   identity.SecurityGroupsLastUpdated.Value.AddDays(7) < clock.GetUtcTime() ||
                !identity.SecurityGroups.Any();
        }

        // It's been an hour since we last refreshed the users groups
        public bool ShouldFetchExternalGroupsInBackground(ActiveDirectoryIdentity identity)
        {
            return identity.SecurityGroupsLastUpdated.HasValue &&
                   identity.SecurityGroupsLastUpdated.Value.AddHours(1) < clock.GetUtcTime();
        }
    }
}