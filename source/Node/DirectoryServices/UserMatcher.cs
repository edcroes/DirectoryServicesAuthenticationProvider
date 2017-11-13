using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Threading;
using Octopus.Data.Model.User;
using Octopus.Node.Extensibility.Authentication.DirectoryServices.Configuration;
using Octopus.Node.Extensibility.Authentication.DirectoryServices.Identities;
using Octopus.Node.Extensibility.Authentication.Extensions;

namespace Octopus.Node.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public class UserMatcher : ICanMatchExternalUser
    {
        readonly IDirectoryServicesContextProvider contextProvider;
        readonly IDirectoryServicesObjectNameNormalizer objectNameNormalizer;
        readonly IDirectoryServicesConfigurationStore configurationStore;
        readonly IIdentityCreator identityCreator;

        public UserMatcher(
            IDirectoryServicesContextProvider contextProvider,
            IDirectoryServicesObjectNameNormalizer objectNameNormalizer,
            IDirectoryServicesConfigurationStore configurationStore,
            IIdentityCreator identityCreator)
        {
            this.contextProvider = contextProvider;
            this.objectNameNormalizer = objectNameNormalizer;
            this.configurationStore = configurationStore;
            this.identityCreator = identityCreator;
        }

        public Identity Match(string name, CancellationToken cancellationToken)
        {
            if (!configurationStore.GetIsEnabled())
                return null;

            string domain;
            string normalisedName;
            objectNameNormalizer.NormalizeName(name, out normalisedName, out domain);

            using (var context = contextProvider.GetContext(domain))
            {
                if (cancellationToken.IsCancellationRequested) return null;

                var userPrincipal = new UserPrincipal(context);

                if (normalisedName.Contains("@"))
                {
                    userPrincipal.UserPrincipalName = normalisedName;
                }
                else
                {
                    userPrincipal.SamAccountName = normalisedName;
                }

                var searcher = new PrincipalSearcher
                {
                    QueryFilter = userPrincipal
                };

                var users = searcher.FindAll();
                if (!users.Any() || users.Count() > 1)
                    return null;

                return users
                    .Select(u => identityCreator.Create("", u.UserPrincipalName, ConvertSamAccountName(u, domain), u.DisplayName))
                    .First();
            }
        }

        static string ConvertSamAccountName(Principal u, string domain)
        {
            return !string.IsNullOrWhiteSpace(domain) ? $"{domain}\\{u.SamAccountName}" : u.SamAccountName;
        }
    }
}