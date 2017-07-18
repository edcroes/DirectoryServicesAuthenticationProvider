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

        public bool ShouldFetchExternalGroups(IUser user)
        {
            var groups = user.GetSecurityGroups(DirectoryServicesAuthenticationProvider.ProviderName);

            if (groups == null)
                return false;

            // Users groups hasn't been retrieved yet, or
            // We haven't been able to update the users groups for a week, or
            // The users groups are empty
            return !groups.LastUpdated.HasValue ||
                   groups.LastUpdated.Value.AddDays(7) < clock.GetUtcTime() ||
                !groups.GroupIds.Any();
        }

        // It's been an hour since we last refreshed the users groups
        public bool ShouldFetchExternalGroupsInBackground(IUser user)
        {
            var groups = user.GetSecurityGroups(DirectoryServicesAuthenticationProvider.ProviderName);

            if (groups == null)
                return false;

            return groups.LastUpdated.HasValue &&
                   groups.LastUpdated.Value.AddHours(1) < clock.GetUtcTime();
        }
    }
}