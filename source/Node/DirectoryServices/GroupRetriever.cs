using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using Octopus.Data.Model.User;
using Octopus.Diagnostics;
using Octopus.Node.Extensibility.Authentication.DirectoryServices.Configuration;
using Octopus.Node.Extensibility.Authentication.DirectoryServices.Identities;
using Octopus.Node.Extensibility.Authentication.Extensions;

namespace Octopus.Node.Extensibility.Authentication.DirectoryServices.DirectoryServices
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
                user.Identities.All(p => p.IdentityProviderName != DirectoryServicesAuthentication.ProviderName))
                return null;

            if (user.Identities.Count(p => p.IdentityProviderName == DirectoryServicesAuthentication.ProviderName) > 1)
            {
                log.WarnFormat("User with username {0} has multiple AD identities, only the first will be used for retrieving groups", user.Username);
            }

            var ad = user.Identities.First(p => p.IdentityProviderName == DirectoryServicesAuthentication.ProviderName);
            
            var result = groupLocator.GetGroupIdsForUser(ad.Claims[IdentityCreator.SamAccountNameClaimType].Value, cancellationToken);
            if (!result.WasAbleToRetrieveGroups)
                return null;

            var newGroups = new HashSet<string>(result.GroupsIds, StringComparer.OrdinalIgnoreCase);
            return new ExternalGroupResult { IdentityProviderName = DirectoryServicesAuthentication.ProviderName, GroupIds = newGroups.Select(g => g).ToArray() };
        }
    }
}