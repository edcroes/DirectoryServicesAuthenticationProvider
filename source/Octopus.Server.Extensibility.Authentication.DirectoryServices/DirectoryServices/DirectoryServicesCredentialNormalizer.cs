using System;
using System.DirectoryServices.AccountManagement;
using Octopus.Server.Extensibility.HostServices.Diagnostics;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public class DirectoryServicesCredentialNormalizer : IDirectoryServicesCredentialNormalizer
    {
        readonly ILog log;
        const string NTAccountUsernamePrefix = "nt:";

        public DirectoryServicesCredentialNormalizer(ILog log)
        {
            this.log = log;
        }

        public void NormalizeCredentials(string username, out string usernamePart, out string domainPart)
        {
            if (username == null) throw new ArgumentNullException(nameof(username));

            if (username.StartsWith(NTAccountUsernamePrefix))
                username = username.Remove(0, NTAccountUsernamePrefix.Length);

            if (!TryParseDownLevelLogonName(username, out usernamePart, out domainPart))
            {
                usernamePart = username;
                domainPart = null;
            }
        }

        public string ValidatedUserPrincipalName(UserPrincipal principal, string fallbackUsername, string fallbackDomain)
        {
            var name = principal.UserPrincipalName;
            if (name == null)
            {
                log.Warn($"The user name (UPN) could not be determined for principal {principal} - falling back to NT-style '{fallbackDomain}\\{fallbackUsername}'");
                if (string.IsNullOrWhiteSpace(fallbackDomain))
                    throw new InvalidOperationException("No fallback domain was provided");
                if (string.IsNullOrWhiteSpace(fallbackUsername))
                    throw new InvalidOperationException("No fallback username was provided");
                name = NTAccountUsernamePrefix + fallbackDomain.Trim() + "\\" + fallbackUsername.Trim();
            }
            return name;
        }

        // If the return value is true, dlln was a valid down-level logon name, and username/domain
        // contain precisely the component username and domain name values. Note, we don't split
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