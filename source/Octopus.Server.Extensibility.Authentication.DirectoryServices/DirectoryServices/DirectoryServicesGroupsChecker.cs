using System;
using System.Collections.Generic;
using System.Threading;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Configuration;
using Octopus.Server.Extensibility.Extensions.Contracts.Authentication;
using Octopus.Server.Extensibility.HostServices.Diagnostics;
using Octopus.Server.Extensibility.HostServices.Model;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public class DirectoryServicesGroupsChecker : IExternalGroupsChecker
    {
        readonly ILog log;
        readonly IUserStore userStore;
        readonly IDirectoryServicesConfigurationStore configurationStore;
        readonly IDirectoryServicesExternalSecurityGroupLocator groupLocator;
        readonly IDirectoryServicesUserSecurityGroupExpiryChecker expiryChecker;

        public DirectoryServicesGroupsChecker(
            ILog log,
            IUserStore userStore,
            IDirectoryServicesConfigurationStore configurationStore,
            IDirectoryServicesExternalSecurityGroupLocator groupLocator,
            IDirectoryServicesUserSecurityGroupExpiryChecker expiryChecker)
        {
            this.log = log;
            this.userStore = userStore;
            this.configurationStore = configurationStore;
            this.groupLocator = groupLocator;
            this.expiryChecker = expiryChecker;
        }

        public HashSet<string> EnsureExternalSecurityGroupsAreUpToDate(IUser user, bool forceRefresh = false)
        {
            if (!configurationStore.GetIsEnabled())
                return new HashSet<string>();

            // We will retrieve the user's external groups when they initially log in.  We can also refresh
            // them in the background periodically.  This is to cater for environments where the group
            // membership is managed outside of Octopus Deploy, e.g. Active Directory, and we need to balance
            // performance vs keeping the group list up to date.
            if (forceRefresh || expiryChecker.ShouldFetchExternalGroups(user))
            {
                try
                {
                    var result = groupLocator.GetGroupIdsForUser(user.Username);
                    if (!result.WasAbleToRetrieveGroups)
                        return new HashSet<string>();

                    var newGroups = new HashSet<string>(result.GroupsIds, StringComparer.OrdinalIgnoreCase);
                    userStore.UpdateUsersExternalGroups(user, newGroups);
                    return newGroups;
                }
                catch (Exception ex)
                {
                    log.Warn(ex, "An error occurred while loading the users external security groups.");
                }
            }
            else if (expiryChecker.ShouldFetchExternalGroupsInBackground(user))
            {
                RefreshMemberExternalSecurityGroups(user);
            }
            return new HashSet<string>();
        }

        void RefreshMemberExternalSecurityGroups(IUser user)
        {
            ThreadPool.QueueUserWorkItem(state =>
            {
                try
                {
                    var result = groupLocator.GetGroupIdsForUser(user.Username);
                    if (!result.WasAbleToRetrieveGroups) return;

                    var groups = new HashSet<string>(result.GroupsIds, StringComparer.OrdinalIgnoreCase);
                    userStore.UpdateUsersExternalGroups(user, groups);
                }
                catch (Exception ex)
                {
                    log.Warn(ex, "An error occurred while refreshing the users external security groups.");
                }
            });
        }
    }
}