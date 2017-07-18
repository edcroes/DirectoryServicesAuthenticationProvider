using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using Octopus.Data.Model.User;
using Octopus.Diagnostics;
using Octopus.Node.Extensibility.Authentication.DirectoryServices.Configuration;
using Octopus.Node.Extensibility.Authentication.Extensions;
using Octopus.Node.Extensibility.Authentication.HostServices;
using Octopus.Time;

namespace Octopus.Node.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public class DirectoryServicesGroupsChecker : IExternalGroupsChecker
    {
        readonly ILog log;
        readonly IUpdateableUserStore userStore;
        readonly IDirectoryServicesConfigurationStore configurationStore;
        readonly IDirectoryServicesExternalSecurityGroupLocator groupLocator;
        readonly IDirectoryServicesUserSecurityGroupExpiryChecker expiryChecker;
        readonly IClock clock;

        public DirectoryServicesGroupsChecker(
            ILog log,
            IUpdateableUserStore userStore,
            IDirectoryServicesConfigurationStore configurationStore,
            IDirectoryServicesExternalSecurityGroupLocator groupLocator,
            IDirectoryServicesUserSecurityGroupExpiryChecker expiryChecker,
            IClock clock)
        {
            this.log = log;
            this.userStore = userStore;
            this.configurationStore = configurationStore;
            this.groupLocator = groupLocator;
            this.expiryChecker = expiryChecker;
            this.clock = clock;
        }

        public HashSet<string> EnsureExternalSecurityGroupsAreUpToDate(IUser user, bool forceRefresh = false)
        {
            if (!configurationStore.GetIsEnabled() || !configurationStore.GetAreSecurityGroupsEnabled())
                return new HashSet<string>();

            var identity = user.Identities.OfType<ActiveDirectoryIdentity>().FirstOrDefault();
            if (identity == null)
                return new HashSet<string>();

            // We will retrieve the user's external groups when they initially log in.  We can also refresh
            // them in the background periodically.  This is to cater for environments where the group
            // membership is managed outside of Octopus Deploy, e.g. Active Directory, and we need to balance
            // performance vs keeping the group list up to date.
            if (forceRefresh || expiryChecker.ShouldFetchExternalGroups(user))
            {
                try
                {
                    var result = groupLocator.GetGroupIdsForUser(identity.SamAccountName);
                    if (!result.WasAbleToRetrieveGroups)
                        return new HashSet<string>();

                    var newGroups = new HashSet<string>(result.GroupsIds, StringComparer.OrdinalIgnoreCase);
                    userStore.SetSecurityGroupIds(DirectoryServicesAuthentication.ProviderName, user.Id, newGroups, clock.GetUtcTime());
                    return newGroups;
                }
                catch (Exception ex)
                {
                    LogWarning(user, identity, ex, "foreground loading");
                }
            }
            else if (expiryChecker.ShouldFetchExternalGroupsInBackground(user))
            {
                RefreshMemberExternalSecurityGroups(user, identity);
            }
            return new HashSet<string>();
        }

        void RefreshMemberExternalSecurityGroups(IUser user, ActiveDirectoryIdentity identity)
        {
            ThreadPool.QueueUserWorkItem(state =>
            {
                try
                {
                    var result = groupLocator.GetGroupIdsForUser(user.Username);
                    if (!result.WasAbleToRetrieveGroups) return;

                    var groups = new HashSet<string>(result.GroupsIds, StringComparer.OrdinalIgnoreCase);
                    userStore.SetSecurityGroupIds(DirectoryServicesAuthentication.ProviderName, user.Id, groups, clock.GetUtcTime());
                }
                catch (Exception ex)
                {
                    LogWarning(user, identity, ex, "background refreshing");
                }
            });
        }

        void LogWarning(IUser user, ActiveDirectoryIdentity identity, Exception ex, string operation)
        {
            log.Warn(ex, $"An error occurred while {operation} the external security groups for the Octopus User Account. This will prevent the Octopus User Account being associated with Octopus Teams. Learn more about external groups: http://g.octopushq.com/ExternalGroupsAndRoles (Username: '{user.Username}' Display Name: '{user.DisplayName}' Email Address: '{user.EmailAddress}' External Identity: '{identity.Upn}').");
        }
    }
}