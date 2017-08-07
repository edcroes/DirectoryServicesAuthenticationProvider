using System;
using System.Collections.Generic;
using System.Linq;
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

        public IEnumerable<ExternalGroupResult> Read(IUser user)
        {
            if (!configurationStore.GetIsEnabled() || !configurationStore.GetAreSecurityGroupsEnabled() || string.IsNullOrWhiteSpace(user.ExternalId))
                return new ExternalGroupResult[] {};

            var result = groupLocator.GetGroupIdsForUser(user.ExternalId);
            if (!result.WasAbleToRetrieveGroups)
                return new ExternalGroupResult[] {};

            var newGroups = new HashSet<string>(result.GroupsIds, StringComparer.OrdinalIgnoreCase);
            return newGroups.Select(g => new ExternalGroupResult { ProviderName = DirectoryServicesAuthenticationProvider.ProviderName, GroupId = g }).ToArray();
        }
    }
}