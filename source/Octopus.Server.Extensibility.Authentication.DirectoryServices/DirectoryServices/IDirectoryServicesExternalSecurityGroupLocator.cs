using System.Collections.Generic;
using Octopus.Server.Extensibility.HostServices.Authentication;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public interface IDirectoryServicesExternalSecurityGroupLocator
    {
        IList<ExternalSecurityGroup> FindGroups(string name);

        DirectoryServicesExternalSecurityGroupLocatorResult GetGroupIdsForUser(string username);
    }
}