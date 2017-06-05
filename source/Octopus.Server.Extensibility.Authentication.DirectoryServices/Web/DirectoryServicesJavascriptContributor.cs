using System.Collections.Generic;
using System.Linq;
using Octopus.Node.Extensibility.Extensions.Infrastructure.Web.Content;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Configuration;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.Web
{
    public class DirectoryServicesJavascriptContributor : IContributesJavascript, IContributesAngularModules
    {
        readonly IDirectoryServicesConfigurationStore configurationStore;

        public DirectoryServicesJavascriptContributor(IDirectoryServicesConfigurationStore configurationStore)
        {
            this.configurationStore = configurationStore;
        }

        public IEnumerable<string> GetAngularModuleNames()
        {
            if (!configurationStore.GetIsEnabled())
                return Enumerable.Empty<string>();
            return new [] { "octopusApp.users.directoryServices" };
        }

        public IEnumerable<string> GetJavascriptUris()
        {
            if (!configurationStore.GetIsEnabled())
                return Enumerable.Empty<string>();

            return new[]
            {
                "~/areas/users/ad_users_module.js",
                "~/areas/users/controllers/ad_auth_provider_controller.js",
                "~/areas/users/directives/ad_auth_provider.js"
            };
        }
    }
}