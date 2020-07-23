using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Octopus.Data;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices;
using Octopus.Server.Extensibility.Authentication.Extensions;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.Web
{
    class ListSecurityGroupsAction : IAsyncApiAction
    {
        readonly IDirectoryServicesExternalSecurityGroupLocator externalSecurityGroupLocator;

        public ListSecurityGroupsAction(
            IDirectoryServicesExternalSecurityGroupLocator externalSecurityGroupLocator)
        {
            this.externalSecurityGroupLocator = externalSecurityGroupLocator;
        }

        public Task ExecuteAsync(OctoContext context)
        {
            var name = context.Request.Query["partialName"]?.FirstOrDefault();
            if (string.IsNullOrWhiteSpace(name))
            {
                context.Response.BadRequest("Please provide the name of a group to search by, or a team");
                return Task.CompletedTask;
            }

            using (var cts = new CancellationTokenSource(TimeSpan.FromMinutes(1)))
            {
                var result = externalSecurityGroupLocator.Search(name, cts.Token);
                if (result is ISuccessResult<ExternalSecurityGroupResult> successResult)
                    context.Response.AsOctopusJson(successResult.Value);
                else
                    context.Response.BadRequest($"The {DirectoryServicesAuthentication.ProviderName} is currently disabled");
            }

            return Task.CompletedTask;
        }
    }
}