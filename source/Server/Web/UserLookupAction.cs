using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.Web
{
    internal class UserLookupAction : IAsyncApiAction
    {
        readonly ICanSearchActiveDirectoryUsers userSearch;

        public UserLookupAction(ICanSearchActiveDirectoryUsers userSearch)
        {
            this.userSearch = userSearch;
        }

        public Task ExecuteAsync(OctoContext context)
        {
            var name = context.Request.Query["partialName"]?.FirstOrDefault();
            if (string.IsNullOrWhiteSpace(name))
            {
                context.Response.BadRequest("Please provide the name of a user to search for");
                return Task.CompletedTask;
            }

            using (var cts = new CancellationTokenSource(TimeSpan.FromMinutes(1)))
            {
                var externalUserLookupResult = userSearch.Search(name, cts.Token);
                if (externalUserLookupResult != null)
                    context.Response.AsOctopusJson(externalUserLookupResult);
                else
                    context.Response.BadRequest($"The {DirectoryServicesAuthentication.ProviderName} is currently disabled");
            }

            return Task.CompletedTask;
        }
    }
}