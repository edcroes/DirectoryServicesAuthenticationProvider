using System.Collections.Generic;
using System.Threading;
using Octopus.Server.Extensibility.Authentication.HostServices;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public interface IDirectoryServicesExternalSecurityGroupLocator
    {
        IList<ExternalSecurityGroup> FindGroups(string name, CancellationToken cancellationToken);

        DirectoryServicesExternalSecurityGroupLocatorResult GetGroupIdsForUser(string externalId, CancellationToken cancellationToken);
    }
}