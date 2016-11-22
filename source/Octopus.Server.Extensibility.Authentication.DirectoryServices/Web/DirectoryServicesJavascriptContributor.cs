using System.Collections.Generic;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Content;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.Web
{
    public class DirectoryServicesJavascriptContributor : IContributesJavascript, IContributesAngularModules
    {
        public IEnumerable<string> GetAngularModuleNames()
        {
            yield return "octopusApp.users.directoryServices";
        }

        public IEnumerable<string> GetJavascriptUris(string requestDirectoryPath)
        {
            yield return "areas/users/ad_users_module.js";
            yield return "areas/users/controllers/ad_auth_provider_controller.js";
            yield return "areas/users/directives/ad_auth_provider.js";
        }
    }
}