using System;
using System.Threading;
using Nancy;
using Octopus.Node.Extensibility.Authentication.DirectoryServices.DirectoryServices;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.Web
{
    public class UserLookupAction : IApiAction
    {
        readonly IApiActionResponseCreator responseCreator;
        readonly ICanSearchActiveDirectoryUsers userSearch;

        public UserLookupAction(
            IApiActionResponseCreator responseCreator,
            ICanSearchActiveDirectoryUsers userSearch)
        {
            this.responseCreator = responseCreator;
            this.userSearch = userSearch;
        }

        public Response Execute(NancyContext context, IResponseFormatter response)
        {
            var name = context.Request.Query["partialName"];
            if (string.IsNullOrWhiteSpace(name))
                return responseCreator.BadRequest("Please provide the name of a user to search for");

            using (var cts = new CancellationTokenSource(TimeSpan.FromMinutes(1)))
            {
                return responseCreator.AsOctopusJson(response, userSearch.Search((string)name, cts.Token));
            }
        }
    }
}