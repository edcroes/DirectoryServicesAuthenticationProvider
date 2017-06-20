using System.DirectoryServices.AccountManagement;
using System.Linq;
using Octopus.Data.Model.User;
using Octopus.Node.Extensibility.Authentication.Extensions;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Configuration;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public class UserMatcher : ICanMatchExternalUser
    {
        readonly IDirectoryServicesContextProvider contextProvider;
        readonly IDirectoryServicesObjectNameNormalizer objectNameNormalizer;
        readonly IDirectoryServicesConfigurationStore configurationStore;

        public UserMatcher(
            IDirectoryServicesContextProvider contextProvider,
            IDirectoryServicesObjectNameNormalizer objectNameNormalizer,
            IDirectoryServicesConfigurationStore configurationStore)
        {
            this.contextProvider = contextProvider;
            this.objectNameNormalizer = objectNameNormalizer;
            this.configurationStore = configurationStore;
        }

        public Identity Match(string name)
        {
            if (!configurationStore.GetIsEnabled())
                return null;

            string domain;
            string normalisedName;
            objectNameNormalizer.NormalizeName(name, out normalisedName, out domain);

            using (var context = contextProvider.GetContext(domain))
            {
                var searcher = new PrincipalSearcher
                {
                    QueryFilter = new UserPrincipal(context) { Name = normalisedName }
                };

                var users = searcher.FindAll();
                if (users.Count() > 1)
                    return null;
                
                return users
                    .Select(u => new ActiveDirectoryIdentity(DirectoryServicesAuthenticationProvider.ProviderName, "", u.UserPrincipalName, u.SamAccountName))
                    .First();
            }
        }
    }
}