using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using Octopus.Data.Model.User;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Configuration;
using Octopus.Server.Extensibility.Authentication.Extensions;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public class GroupRetriever : IExternalGroupRetriever
    {
        readonly IDirectoryServicesConfigurationStore configurationStore;
        readonly IDirectoryServicesExternalSecurityGroupLocator groupLocator;

        public GroupRetriever(IDirectoryServicesConfigurationStore configurationStore, IDirectoryServicesExternalSecurityGroupLocator groupLocator)
        {
            this.configurationStore = configurationStore;
            this.groupLocator = groupLocator;
        }

        public ExternalGroupResult Read(IUser user, CancellationToken cancellationToken)
        {
            if (!configurationStore.GetIsEnabled() || !configurationStore.GetAreSecurityGroupsEnabled() || string.IsNullOrWhiteSpace(user.ExternalId))
                return null;
            
            var result = groupLocator.GetGroupIdsForUser(user.ExternalId, cancellationToken);
            if (!result.WasAbleToRetrieveGroups)
                return null;

            var newGroups = new HashSet<string>(result.GroupsIds, StringComparer.OrdinalIgnoreCase);
            return new ExternalGroupResult { ProviderName = DirectoryServicesAuthenticationProvider.ProviderName, GroupIds = newGroups.Select(g => g).ToArray() };
        }
    }
}