using System.Collections.Generic;
using System.Linq;
using Octopus.Node.Extensibility.Extensions.Infrastructure.Web.Content;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Configuration;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.Web
{
    public class DirectoryServicesCSSContributor : IContributesCSS
    {
        readonly IDirectoryServicesConfigurationStore configurationStore;

        public DirectoryServicesCSSContributor(IDirectoryServicesConfigurationStore configurationStore)
        {
            this.configurationStore = configurationStore;
        }

        public IEnumerable<string> GetCSSUris()
        {
            if (!configurationStore.GetIsEnabled())
                return Enumerable.Empty<string>();
            return new [] { "~/styles/DirectoryServices.css" };
        }
    }
}