using System;
using System.Collections.Generic;
using System.Threading;
using Octopus.Data.Model.User;
using Octopus.Data.Storage.User;
using Octopus.Diagnostics;
using Octopus.Node.Extensibility.Authentication.Extensions;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Configuration;

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
            if (!configurationStore.GetIsEnabled() || !configurationStore.GetAreSecurityGroupsEnabled() || string.IsNullOrWhiteSpace(user.ExternalId))
                return new HashSet<string>();

            // We will retrieve the user's external groups when they initially log in.  We can also refresh
            // them in the background periodically.  This is to cater for environments where the group
            // membership is managed outside of Octopus Deploy, e.g. Active Directory, and we need to balance
            // performance vs keeping the group list up to date.
            if (forceRefresh || expiryChecker.ShouldFetchExternalGroups(user))
            {
                try
                {
                    var result = groupLocator.GetGroupIdsForUser(user.ExternalId);
                    if (!result.WasAbleToRetrieveGroups)
                        return new HashSet<string>();

                    var newGroups = new HashSet<string>(result.GroupsIds, StringComparer.OrdinalIgnoreCase);
                    userStore.UpdateUsersExternalGroups(user, newGroups);
                    return newGroups;
                }
                catch (Exception ex)
                {
                    LogWarning(user, ex, "foreground loading");
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
                    LogWarning(user, ex, "background refreshing");
                }
            });
        }

        void LogWarning(IUser user, Exception ex, string operation)
        {
            log.Warn(ex, $"An error occurred while {operation} the external security groups for the Octopus User Account. This will prevent the Octopus User Account being associated with Octopus Teams. Learn more about external groups: http://g.octopushq.com/ExternalGroupsAndRoles (Username: '{user.Username}' Display Name: '{user.DisplayName}' Email Address: '{user.EmailAddress}' External Identity: '{user.ExternalId}').");
        }
    }
}