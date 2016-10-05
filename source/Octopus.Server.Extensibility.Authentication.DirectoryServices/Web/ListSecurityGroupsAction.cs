using System.Collections.Generic;
using Nancy;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;
using Octopus.Server.Extensibility.HostServices.Authentication;

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
            var name = context.Request.Query["name"];
            if (string.IsNullOrWhiteSpace(name))
                return responseCreator.BadRequest("Please provide the name of a group to search by, or a team");

            return responseCreator.AsOctopusJson(response, SearchByName(name));
        }

        IList<ExternalSecurityGroup> SearchByName(string name)
        {
            return externalSecurityGroupLocator.FindGroups(name);
        }
    }
}