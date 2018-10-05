using System;
using System.Threading;
using System.Threading.Tasks;
using Octopus.Node.Extensibility.Authentication.DirectoryServices.DirectoryServices;
using Octopus.Node.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.Web
{
    public class ListSecurityGroupsAction : IAsyncApiAction
    {
        readonly IDirectoryServicesExternalSecurityGroupLocator externalSecurityGroupLocator;

        public ListSecurityGroupsAction(
            IDirectoryServicesExternalSecurityGroupLocator externalSecurityGroupLocator)
        {
            this.externalSecurityGroupLocator = externalSecurityGroupLocator;
        }

        public Task ExecuteAsync(OctoContext context)
        {
            var name = context.Request.Query["partialName"];
            if (string.IsNullOrWhiteSpace(name))
            {
                context.Response.BadRequest("Please provide the name of a group to search by, or a team");
                return Task.FromResult(0);
            }

            using (var cts = new CancellationTokenSource(TimeSpan.FromMinutes(1)))
            {
                context.Response.AsOctopusJson(SearchByName(name, cts.Token));
            }

            return Task.FromResult(0);
        }

        ExternalSecurityGroup[] SearchByName(string name, CancellationToken cancellationToken)
        {
            return externalSecurityGroupLocator.Search(name, cancellationToken).Groups;
        }
    }
}