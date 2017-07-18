using System.DirectoryServices.AccountManagement;
using System.Linq;
using Octopus.Data.Model.User;
using Octopus.Node.Extensibility.Authentication.DirectoryServices.Configuration;
using Octopus.Node.Extensibility.Authentication.Extensions;

namespace Octopus.Node.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public class UserLookup : ICanLookupExternalUsers
    {
        readonly IDirectoryServicesContextProvider contextProvider;
        readonly IDirectoryServicesObjectNameNormalizer objectNameNormalizer;
        readonly IDirectoryServicesConfigurationStore configurationStore;

        public UserLookup(
            IDirectoryServicesContextProvider contextProvider,
            IDirectoryServicesObjectNameNormalizer objectNameNormalizer,
            IDirectoryServicesConfigurationStore configurationStore)
        {
            this.contextProvider = contextProvider;
            this.objectNameNormalizer = objectNameNormalizer;
            this.configurationStore = configurationStore;
        }

        public Identity[] Search(string provider, string searchTerm)
        {
            if (!configurationStore.GetIsEnabled() || provider != DirectoryServicesAuthentication.ProviderName)
                return Enumerable.Empty<Identity>().ToArray();

            string domain;
            string partialName;
            objectNameNormalizer.NormalizeName(searchTerm, out partialName, out domain);

            using (var context = contextProvider.GetContext(domain))
            {
                var searcher = new PrincipalSearcher
                {
                    QueryFilter = new UserPrincipal(context) {Name = partialName + "*"}
                };

                return searcher.FindAll()
                    .Select(u => new ActiveDirectoryIdentity(DirectoryServicesAuthentication.ProviderName, "", u.UserPrincipalName, u.SamAccountName))
                    .ToArray();
            }
        }
    }
}