using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using Octopus.Data.Model.User;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Configuration;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Identities;
using Octopus.Server.Extensibility.Authentication.Extensions;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public class GroupRetriever : IExternalGroupRetriever
    {
        readonly ILog log;
        readonly IDirectoryServicesConfigurationStore configurationStore;
        readonly IDirectoryServicesExternalSecurityGroupLocator groupLocator;

        public GroupRetriever(
            ILog log,
            IDirectoryServicesConfigurationStore configurationStore, 
            IDirectoryServicesExternalSecurityGroupLocator groupLocator)
        {
            this.log = log;
            this.configurationStore = configurationStore;
            this.groupLocator = groupLocator;
        }

        public ExternalGroupResult Read(IUser user, CancellationToken cancellationToken)
        {
            if (!configurationStore.GetIsEnabled() ||
                !configurationStore.GetAreSecurityGroupsEnabled() || 
                user.Username == User.GuestLogin ||
                user.Identities.All(p => p.IdentityProviderName != DirectoryServicesAuthenticationProvider.ProviderName))
                return new ExternalGroupResult { IdentityProviderName = DirectoryServicesAuthenticationProvider.ProviderName, GroupIds = Enumerable.Empty<string>() };

            // if the user has multiple, unique identities assigned then the group list should be the distinct union of the groups from
            // all of the identities
            var wasAbleToRetrieveSomeGroups = false;
            var newGroups = new HashSet<string>();
            var adIdentities = user.Identities.Where(p => p.IdentityProviderName == DirectoryServicesAuthenticationProvider.ProviderName);
            foreach (var adIdentity in adIdentities)
            {
                var samAccountName = adIdentity.Claims[IdentityCreator.SamAccountNameClaimType].Value;

                var result = groupLocator.GetGroupIdsForUser(samAccountName, cancellationToken);
                if (result.WasAbleToRetrieveGroups)
                {
                    foreach (var groupId in result.GroupsIds.Where(g => !newGroups.Contains(g)))
                    {
                        newGroups.Add(groupId);
                    }
                    wasAbleToRetrieveSomeGroups = true;
                }
                else
                {
                    log.WarnFormat("Couldn't retrieve groups for samAccountName {0}", samAccountName);
                }
            }

            if (!wasAbleToRetrieveSomeGroups)
            {
                log.ErrorFormat("Couldn't retrieve groups for user {0}", user.Username);
                return new ExternalGroupResult { IdentityProviderName = DirectoryServicesAuthenticationProvider.ProviderName, GroupIds = Enumerable.Empty<string>() };
            }

            return new ExternalGroupResult { IdentityProviderName = DirectoryServicesAuthenticationProvider.ProviderName, GroupIds = newGroups.Select(g => g).ToArray() };
        }
    }
}