using System.Collections.Generic;
using Octopus.Node.Extensibility.Authentication.HostServices;

namespace Octopus.Node.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public interface IDirectoryServicesExternalSecurityGroupLocator
    {
        IList<ExternalSecurityGroup> FindGroups(string name);

        DirectoryServicesExternalSecurityGroupLocatorResult GetGroupIdsForUser(string samAccountName);
    }
}