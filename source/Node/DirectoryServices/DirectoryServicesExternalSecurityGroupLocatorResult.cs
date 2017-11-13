using System.Collections.Generic;

namespace Octopus.Node.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public class DirectoryServicesExternalSecurityGroupLocatorResult
    {
        public DirectoryServicesExternalSecurityGroupLocatorResult()
        {
        }

        public DirectoryServicesExternalSecurityGroupLocatorResult(IList<string> groupsIds)
        {
            WasAbleToRetrieveGroups = true;
            GroupsIds = groupsIds;
        }

        public bool WasAbleToRetrieveGroups { get; set; }
        public IList<string> GroupsIds { get; set; }
    }
}