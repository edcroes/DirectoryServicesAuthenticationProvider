using System.Collections.Generic;
using Octopus.Node.Extensibility.HostServices.Web;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Configuration;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public class DirectoryServicesHomeLinksContributor : IHomeLinksContributor
    {
        readonly IDirectoryServicesConfigurationStore configurationStore;

        public DirectoryServicesHomeLinksContributor(IDirectoryServicesConfigurationStore configurationStore)
        {
            this.configurationStore = configurationStore;
        }

        public IDictionary<string,string> GetLinksToContribute()
        {
            var linksToContribute = new Dictionary<string, string>();

            if (configurationStore.GetIsEnabled())
            {
                linksToContribute.Add("IntegratedAuthenticationChallenge", "~" + DirectoryServicesConstants.ChallengePath);
            }

            return linksToContribute;
        }
    }
}