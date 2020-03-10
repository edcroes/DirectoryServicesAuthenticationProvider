using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.Web
{
    class UserLookupAction : IAsyncApiAction
    {
        readonly ICanSearchActiveDirectoryUsers userSearch;

        public UserLookupAction(
            ICanSearchActiveDirectoryUsers userSearch)
        {
            this.userSearch = userSearch;
        }

        public Task ExecuteAsync(OctoContext context)
        {
            var name = context.Request.Query["partialName"]?.FirstOrDefault();
            if (string.IsNullOrWhiteSpace(name))
            {
                context.Response.BadRequest("Please provide the name of a user to search for");
                return Task.FromResult(0);
            }

            using (var cts = new CancellationTokenSource(TimeSpan.FromMinutes(1)))
            {
                context.Response.AsOctopusJson(userSearch.Search(name, cts.Token));
            }

            return Task.FromResult(0);
        }
    }
}