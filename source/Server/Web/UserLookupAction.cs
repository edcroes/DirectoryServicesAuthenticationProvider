using System;
using System.Threading;
using System.Threading.Tasks;
using Octopus.Node.Extensibility.Authentication.DirectoryServices.DirectoryServices;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.Web
{
    public class UserLookupAction : IAsyncApiAction
    {
        readonly ICanSearchActiveDirectoryUsers userSearch;

        public UserLookupAction(
            ICanSearchActiveDirectoryUsers userSearch)
        {
            this.userSearch = userSearch;
        }

        public Task ExecuteAsync(OctoContext context)
        {
            var name = context.Request.Query["partialName"];
            if (string.IsNullOrWhiteSpace(name))
            {
                context.Response.BadRequest("Please provide the name of a user to search for");
                return Task.CompletedTask;
            }

            using (var cts = new CancellationTokenSource(TimeSpan.FromMinutes(1)))
            {
                context.Response.AsOctopusJson(userSearch.Search(name, cts.Token));
            }

            return Task.CompletedTask;
        }
    }
}