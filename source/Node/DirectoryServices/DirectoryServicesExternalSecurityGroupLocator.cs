using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Threading;
using Octopus.Diagnostics;
using Octopus.Node.Extensibility.Authentication.DirectoryServices.Configuration;
using Octopus.Node.Extensibility.Authentication.HostServices;

namespace Octopus.Node.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public class DirectoryServicesExternalSecurityGroupLocator : IDirectoryServicesExternalSecurityGroupLocator
    {
        readonly ILog log;
        readonly IDirectoryServicesContextProvider contextProvider;
        readonly IDirectoryServicesObjectNameNormalizer objectNameNormalizer;
        readonly IDirectoryServicesConfigurationStore configurationStore;

        public DirectoryServicesExternalSecurityGroupLocator(
            ILog log,
            IDirectoryServicesContextProvider contextProvider,
            IDirectoryServicesObjectNameNormalizer objectNameNormalizer,
            IDirectoryServicesConfigurationStore configurationStore)
        {
            this.log = log;
            this.contextProvider = contextProvider;
            this.objectNameNormalizer = objectNameNormalizer;
            this.configurationStore = configurationStore;
        }

        public IList<ExternalSecurityGroup> FindGroups(string name, CancellationToken cancellationToken)
        {
            if (!configurationStore.GetAreSecurityGroupsEnabled())
                return new List<ExternalSecurityGroup>();

            var results = new List<ExternalSecurityGroup>();
            string domain;
            string partialGroupName;
            objectNameNormalizer.NormalizeName(name, out partialGroupName, out domain);
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

                        if (cancellationToken.IsCancellationRequested) return null;
                    }
                }
            }

            return results.OrderBy(o => o.DisplayName).ToList();
        }

        public DirectoryServicesExternalSecurityGroupLocatorResult GetGroupIdsForUser(string samAccountName, CancellationToken cancellationToken)
        {
            if (samAccountName == null) throw new ArgumentNullException(nameof(samAccountName), "The external identity is null indicating we were not able to associate this Octopus User Account with an identifier from Active Directory.");

            if (!configurationStore.GetAreSecurityGroupsEnabled())
                return new DirectoryServicesExternalSecurityGroupLocatorResult(new List<string>());

            var groups = new List<string>();

            try
            {
                log.Verbose($"Finding external security groups for '{samAccountName}'...");

                objectNameNormalizer.NormalizeName(samAccountName, out samAccountName, out var domain);

                using (var context = contextProvider.GetContext(domain))
                {
                    var principal = UserPrincipal.FindByIdentity(context, samAccountName);
                    if (principal == null)
                    {
                        var searchedContext = domain ?? context.Name ?? context.ConnectedServer;
                        log.Trace(
                            $"While loading security groups, a principal identifiable by '{samAccountName}' was not found in '{searchedContext}'");
                        return new DirectoryServicesExternalSecurityGroupLocatorResult();
                    }

                    try
                    {
                        // Reads inherited groups - this fails in some situations
                        ReadAuthorizationGroups(principal, groups, cancellationToken);
                    }
                    catch (Exception ex)
                    {
                        // Don't log it as an Error, it's expected to fail in some situations
                        log.Verbose(ex);

                        try
                        {
                            // Reads just the groups they are a member of - more reliable but not ideal
                            ReadUserGroups(principal, groups, cancellationToken);
                        }
                        catch (Exception ex2)
                        {
                            // Only log an error if both methods fail to read the groups
                            log.Error(ex2);

                            return new DirectoryServicesExternalSecurityGroupLocatorResult();
                        }
                    }
                }

                if (cancellationToken.IsCancellationRequested)
                    return new DirectoryServicesExternalSecurityGroupLocatorResult();
            }
            catch (Exception ex)
            {
                log.ErrorFormat(ex, "Active Directory search for {0} failed.", samAccountName);
                return new DirectoryServicesExternalSecurityGroupLocatorResult();
            }

            return new DirectoryServicesExternalSecurityGroupLocatorResult(groups);
        }

        static void ReadAuthorizationGroups(UserPrincipal principal, ICollection<string> groups, CancellationToken cancellationToken)
        {
            ReadGroups(principal.GetAuthorizationGroups(), groups, cancellationToken);
        }

        static void ReadUserGroups(Principal principal, ICollection<string> groups, CancellationToken cancellationToken)
        {
            ReadGroups(principal.GetGroups(), groups, cancellationToken);
        }

        static void ReadGroups(IEnumerable<Principal> groupPrincipals, ICollection<string> groups, CancellationToken cancellationToken)
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

                        if (cancellationToken.IsCancellationRequested) return;
                    }
                    catch (NoMatchingPrincipalException)
                    {
                    }
                }
            }
        }
    }
}