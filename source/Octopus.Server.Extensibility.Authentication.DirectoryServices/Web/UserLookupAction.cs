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
            var name = context.Request.Query["name"];

            using (var cts = new CancellationTokenSource(TimeSpan.FromMinutes(1)))
            {
                return responseCreator.AsOctopusJson(response, userLookup.Search(name, cts.Token));
            }
        }
    }
}