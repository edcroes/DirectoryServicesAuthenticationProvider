using System.Collections.Generic;
using Octopus.Node.Extensibility.Authentication.HostServices;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public interface IDirectoryServicesExternalSecurityGroupLocator
    {
        IList<ExternalSecurityGroup> FindGroups(string name);

        DirectoryServicesExternalSecurityGroupLocatorResult GetGroupIdsForUser(string externalId);
    }
}