using System;
using System.Threading;
using Nancy;
using Octopus.Node.Extensibility.Authentication.DirectoryServices.DirectoryServices;
using Octopus.Node.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.Web
{
    public class ListSecurityGroupsAction : IApiAction
    {
        readonly IDirectoryServicesExternalSecurityGroupLocator externalSecurityGroupLocator;
        readonly IApiActionResponseCreator responseCreator;

        public ListSecurityGroupsAction(
            IDirectoryServicesExternalSecurityGroupLocator externalSecurityGroupLocator,
            IApiActionResponseCreator responseCreator)
        {
            this.externalSecurityGroupLocator = externalSecurityGroupLocator;
            this.responseCreator = responseCreator;
        }

        public Response Execute(NancyContext context, IResponseFormatter response)
        {
            var name = context.Request.Query["partialName"];
            if (string.IsNullOrWhiteSpace(name))
                return responseCreator.BadRequest("Please provide the name of a group to search by, or a team");

            using (var cts = new CancellationTokenSource(TimeSpan.FromMinutes(1)))
            {
                return responseCreator.AsOctopusJson(response, SearchByName(name, cts.Token));
            }
        }

        ExternalSecurityGroup[] SearchByName(string name, CancellationToken cancellationToken)
        {
            return externalSecurityGroupLocator.Search(name, cancellationToken).Groups;
        }
    }
}