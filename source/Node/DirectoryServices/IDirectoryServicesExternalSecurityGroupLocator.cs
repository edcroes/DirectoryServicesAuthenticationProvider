using System.Collections.Generic;
using System.Threading;
using Octopus.Node.Extensibility.Authentication.HostServices;

namespace Octopus.Node.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public interface IDirectoryServicesExternalSecurityGroupLocator
    {
        IList<ExternalSecurityGroup> FindGroups(string name, CancellationToken cancellationToken);

        DirectoryServicesExternalSecurityGroupLocatorResult GetGroupIdsForUser(string samAccountName, CancellationToken cancellationToken);
    }
}