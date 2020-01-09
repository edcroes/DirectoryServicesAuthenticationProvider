using System;
using Octopus.Diagnostics;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public class DirectoryServicesObjectNameNormalizer : IDirectoryServicesObjectNameNormalizer
    {
        readonly ISystemLog log;
        const string NTAccountUsernamePrefix = "nt:";

        public DirectoryServicesObjectNameNormalizer(ISystemLog log)
        {
            this.log = log;
        }

        public void NormalizeName(string name, out string namePart, out string domainPart)
        {
            if (name == null) throw new ArgumentNullException(nameof(name));

            if (name.StartsWith(NTAccountUsernamePrefix))
                name = name.Remove(0, NTAccountUsernamePrefix.Length);

            if (!TryParseDownLevelLogonName(name, out namePart, out domainPart))
            {
                namePart = name;
                domainPart = null;
            }
        }

        public string ValidatedUserPrincipalName(string userPrincipalName, string fallbackUsername, string fallbackDomain)
        {
            var name = userPrincipalName;
            if (name == null)
            {
                log.Warn($"The user name (UPN) could not be determined for principal - falling back to NT-style '{fallbackDomain}\\{fallbackUsername}'");
                if (string.IsNullOrWhiteSpace(fallbackDomain))
                    throw new InvalidOperationException("No fallback domain was provided");
                if (string.IsNullOrWhiteSpace(fallbackUsername))
                    throw new InvalidOperationException("No fallback name was provided");
                name = NTAccountUsernamePrefix + fallbackDomain.Trim() + "\\" + fallbackUsername.Trim();
            }
            return name;
        }

        // If the return value is true, dlln was a valid down-level logon name, and name/domain
        // contain precisely the component name and domain name values. Note, we don't split
        // UPNs this way because the suffix part of a UPN is not necessarily a domain, and in
        // the default LogonUser case should be passed whole to the function with a null domain.
        static bool TryParseDownLevelLogonName(string dlln, out string username, out string domain)
        {
            if (dlln == null) throw new ArgumentNullException(nameof(dlln));
            username = null;
            domain = null;

            var slash = dlln.IndexOf('\\');
            if (slash == -1 || slash == dlln.Length - 1 || slash == 0)
                return false;

            domain = dlln.Substring(0, slash).Trim();
            username = dlln.Substring(slash + 1).Trim();
            return !string.IsNullOrWhiteSpace(domain) && !string.IsNullOrWhiteSpace(username);
        }
    }
}