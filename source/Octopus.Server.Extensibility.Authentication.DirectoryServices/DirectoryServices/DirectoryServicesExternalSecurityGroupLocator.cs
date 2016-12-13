using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Configuration;
using Octopus.Server.Extensibility.Authentication.HostServices;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public class DirectoryServicesExternalSecurityGroupLocator : IDirectoryServicesExternalSecurityGroupLocator
    {
        readonly ILog log;
        readonly IDirectoryServicesContextProvider contextProvider;
        readonly IDirectoryServicesCredentialNormalizer credentialNormalizer;
        readonly IDirectoryServicesConfigurationStore configurationStore;

        public DirectoryServicesExternalSecurityGroupLocator(
            ILog log,
            IDirectoryServicesContextProvider contextProvider,
            IDirectoryServicesCredentialNormalizer credentialNormalizer,
            IDirectoryServicesConfigurationStore configurationStore)
        {
            this.log = log;
            this.contextProvider = contextProvider;
            this.credentialNormalizer = credentialNormalizer;
            this.configurationStore = configurationStore;
        }

        public IList<ExternalSecurityGroup> FindGroups(string name)
        {
            if (!configurationStore.GetAreSecurityGroupsEnabled())
                return new List<ExternalSecurityGroup>();

            var results = new List<ExternalSecurityGroup>();
            string domain;
            string partialGroupName;
            credentialNormalizer.NormalizeCredentials(name, out partialGroupName, out domain);
            using (var context = contextProvider.GetContext(domain))
            {
                var searcher = new PrincipalSearcher();
                searcher.QueryFilter = new GroupPrincipal(context) { Name = partialGroupName + "*" };

                var iterGroup = searcher.FindAll().GetEnumerator();
                using (iterGroup)
                {
                    while (iterGroup.MoveNext())
                    {
                        try
                        {
                            var p = iterGroup.Current as GroupPrincipal;
                            if (p == null || !(p.IsSecurityGroup ?? false))
                                continue;

                            results.Add(new ExternalSecurityGroup { Id = p.Sid.ToString(), DisplayName = p.Name });
                        }
                        catch (NoMatchingPrincipalException)
                        {
                        }
                    }
                }
            }

            return results.OrderBy(o => o.DisplayName).ToList();
        }

        public DirectoryServicesExternalSecurityGroupLocatorResult GetGroupIdsForUser(string externalId)
        {
            if (externalId == null) throw new ArgumentNullException("externalId");

            if (!configurationStore.GetAreSecurityGroupsEnabled())
                return new DirectoryServicesExternalSecurityGroupLocatorResult(new List<string>());

            log.Verbose($"Finding external security groups for '{externalId}'...");

            string domain;
            credentialNormalizer.NormalizeCredentials(externalId, out externalId, out domain);

            var groups = new List<string>();

            using (var context = contextProvider.GetContext(domain))
            {
                var principal = UserPrincipal.FindByIdentity(context, externalId);
                if (principal == null)
                {
                    var searchedContext = domain ?? context.Name ?? context.ConnectedServer;
                    log.Trace($"While loading security groups, a principal identifiable by '{externalId}' was not found in '{searchedContext}'");
                    return new DirectoryServicesExternalSecurityGroupLocatorResult();
                }

                try
                {
                    // Reads inherited groups - this fails in some situations
                    ReadAuthorizationGroups(principal, groups);
                }
                catch (Exception ex)
                {
                    // Don't log it as an Error, it's expected to fail in some situations
                    log.Verbose(ex);

                    try
                    {
                        // Reads just the groups they are a member of - more reliable but not ideal
                        ReadUserGroups(principal, groups);
                    }
                    catch (Exception ex2)
                    {
                        // Only log an error if both methods fail to read the groups
                        log.Error(ex2);

                        return new DirectoryServicesExternalSecurityGroupLocatorResult();
                    }
                }
            }

            return new DirectoryServicesExternalSecurityGroupLocatorResult(groups);
        }

        static void ReadAuthorizationGroups(UserPrincipal principal, ICollection<string> groups)
        {
            ReadGroups(principal.GetAuthorizationGroups(), groups);
        }

        static void ReadUserGroups(Principal principal, ICollection<string> groups)
        {
            ReadGroups(principal.GetGroups(), groups);
        }

        static void ReadGroups(IEnumerable<Principal> groupPrincipals, ICollection<string> groups)
        {
            var iterGroup = groupPrincipals.GetEnumerator();
            using (iterGroup)
            {
                while (iterGroup.MoveNext())
                {
                    try
                    {
                        var p = iterGroup.Current;
                        groups.Add(p.Sid.Value);
                    }
                    catch (NoMatchingPrincipalException)
                    {
                    }
                }
            }
        }
    }
}