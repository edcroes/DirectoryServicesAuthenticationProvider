using System;
using System.Threading;
using Nancy;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.Web
{
    public class UserLookupAction : IApiAction
    {
        readonly IApiActionResponseCreator responseCreator;
        readonly ICanLookupActiveDirectoryUsers userLookup;

        public UserLookupAction(
            IApiActionResponseCreator responseCreator,
            ICanLookupActiveDirectoryUsers userLookup)
        {
            this.responseCreator = responseCreator;
            this.userLookup = userLookup;
        }

        public Response Execute(NancyContext context, IResponseFormatter response)
        {
            var name = context.Request.Query["partialName"];
            if (string.IsNullOrWhiteSpace(name))
                return responseCreator.BadRequest("Please provide the name of a user to search for");

            using (var cts = new CancellationTokenSource(TimeSpan.FromMinutes(1)))
            {
                return responseCreator.AsOctopusJson(response, userLookup.Search((string)name, cts.Token));
            }
        }
    }
}