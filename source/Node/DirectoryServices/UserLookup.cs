using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Threading;
using Octopus.Data.Resources.Users;
using Octopus.Node.Extensibility.Authentication.DirectoryServices.Configuration;
using Octopus.Node.Extensibility.Authentication.DirectoryServices.Identities;
using Octopus.Node.Extensibility.Authentication.Extensions;

namespace Octopus.Node.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public class UserLookup : ICanLookupActiveDirectoryUsers
    {
        readonly IDirectoryServicesContextProvider contextProvider;
        readonly IDirectoryServicesObjectNameNormalizer objectNameNormalizer;
        readonly IDirectoryServicesConfigurationStore configurationStore;
        readonly IIdentityCreator identityCreator;

        public UserLookup(
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

        public ExternalUserLookupResult Search(string searchTerm, CancellationToken cancellationToken)
        {
            if (!configurationStore.GetIsEnabled())
                return new ExternalUserLookupResult (DirectoryServicesAuthentication.ProviderName, Enumerable.Empty<IdentityResource>().ToArray());

            string domain;
            string partialName;
            objectNameNormalizer.NormalizeName(searchTerm, out partialName, out domain);

            using (var context = contextProvider.GetContext(domain))
            {
                if (cancellationToken.IsCancellationRequested) return null;

                var searcher = new PrincipalSearcher
                {
                    QueryFilter = new UserPrincipal(context) { Name = partialName + "*" }
                };

                var identities = searcher.FindAll()
                    .Select(u => identityCreator.Create("", u.UserPrincipalName, ConvertSamAccountName(u, domain), u.DisplayName).ToResource())
                    .ToArray();
                return new ExternalUserLookupResult(DirectoryServicesAuthentication.ProviderName, identities);
            }
        }

        static string ConvertSamAccountName(Principal u, string domain)
        {
            return !string.IsNullOrWhiteSpace(domain) ? $"{domain}\\{u.SamAccountName}" : u.SamAccountName;
        }
    }

    public interface ICanLookupActiveDirectoryUsers : ICanLookupExternalUsers
    { }
}