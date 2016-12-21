using System;
using System.ComponentModel;
using System.DirectoryServices.AccountManagement;
using System.Runtime.InteropServices;
using Octopus.Data.Storage.User;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Configuration;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public class DirectoryServicesCredentialValidator : IDirectoryServicesCredentialValidator
    {
        /// <summary>
        /// This logon type is intended for high performance servers to authenticate plaintext passwords.
        /// The LogonUser function does not cache credentials for this logon type.
        /// </summary>
        const int LOGON32_LOGON_NETWORK = 3;

        /// <summary>
        /// Use the standard logon provider for the system.
        /// The default security provider is negotiate, unless you pass NULL for the domain name and the user name
        /// is not in UPN format. In this case, the default provider is NTLM.
        /// NOTE: Windows 2000/NT:   The default security provider is NTLM.
        /// </summary>
        const int LOGON32_PROVIDER_DEFAULT = 0;

        readonly ILog log;
        readonly IDirectoryServicesObjectNameNormalizer objectNameNormalizer;
        readonly IDirectoryServicesContextProvider contextProvider;
        readonly IUserStore userStore;
        readonly IDirectoryServicesConfigurationStore configurationStore;

        public DirectoryServicesCredentialValidator(
            ILog log, 
            IDirectoryServicesObjectNameNormalizer objectNameNormalizer,
            IDirectoryServicesContextProvider contextProvider,
            IUserStore userStore,
            IDirectoryServicesConfigurationStore configurationStore)
        {
            this.log = log;
            this.objectNameNormalizer = objectNameNormalizer;
            this.contextProvider = contextProvider;
            this.userStore = userStore;
            this.configurationStore = configurationStore;
        }

        public UserCreateOrUpdateResult ValidateCredentials(string username, string password)
        {
            if (!configurationStore.GetIsEnabled() || 
                !configurationStore.GetAllowFormsAuthenticationForDomainUsers())
            {
                return new UserCreateOrUpdateResult("Directory services forms authentication is not enabled");
            }

            if (username == null) throw new ArgumentNullException(nameof(username));

            log.Verbose($"Validating credentials provided for '{username}'...");

            string domain;
            objectNameNormalizer.NormalizeName(username, out username, out domain);

            using (var context = contextProvider.GetContext(domain))
            {
                var principal = UserPrincipal.FindByIdentity(context, username);

                if (principal == null)
                {
                    var searchedContext = domain ?? context.Name ?? context.ConnectedServer;
                    log.Info($"A principal identifiable by '{username}' was not found in '{searchedContext}'");
                    if (username.Contains("@"))
                    {
                        return new UserCreateOrUpdateResult("Username not found.  UPN format may not be supported for your domain configuration.");
                    }
                    return new UserCreateOrUpdateResult("Username not found");
                }

                var hToken = IntPtr.Zero;
                try
                {
                    var logon = domain == null ? principal.UserPrincipalName : username;
                    log.Verbose($"Calling LogonUser(\"{logon}\", \"{domain}\", ...)");

                    if (!LogonUser(logon, domain, password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, out hToken))
                    {
                        var error = new Win32Exception();
                        log.Warn(error, $"Principal '{logon}' (Domain: '{domain}') could not be logged on via WIN32: 0x{error.NativeErrorCode:X8}.");

                        return new UserCreateOrUpdateResult("Active directory login error");
                    }
                }
                finally
                {
                    if (hToken != IntPtr.Zero) CloseHandle(hToken);
                }

                log.Verbose($"Credentials for '{username}' validated, mapped to principal '{principal.UserPrincipalName ?? ("(NTAccount)" + principal.Name)}'");

                return GetOrCreateUser(principal, username, domain);
            }
        }

        public UserCreateOrUpdateResult GetOrCreateUser(string username)
        {
            string domain;
            objectNameNormalizer.NormalizeName(username, out username, out domain);

            using (var context = contextProvider.GetContext(domain))
            {
                var principal = UserPrincipal.FindByIdentity(context, username);
                if (principal == null)
                {
                    var searchedContext = domain ?? context.Name ?? context.ConnectedServer;
                    throw new ArgumentException($"A principal identifiable by '{username}' was not found in '{searchedContext}'");
                }

                return GetOrCreateUser(principal, username, domain ?? Environment.UserDomainName);
            }
        }

        UserCreateOrUpdateResult GetOrCreateUser(UserPrincipal principal, string fallbackUsername, string fallbackDomain)
        {
            var username = objectNameNormalizer.ValidatedUserPrincipalName(principal, fallbackUsername, fallbackDomain);

            var externalId = principal.SamAccountName;
            if (!string.IsNullOrWhiteSpace(fallbackDomain))
            {
                externalId = fallbackDomain + @"\" + externalId;
            }

            var displayName = string.IsNullOrWhiteSpace(principal.DisplayName) ? principal.Name : principal.DisplayName;
            var emailAddress = principal.EmailAddress;

            if (string.IsNullOrWhiteSpace(externalId))
            {
                log.Error($"We couldn't find a valid external identity to use for the Active Directory user '{displayName}' with email address '{emailAddress}' for the Octopus User Account named '{username}'. Octopus uses the samAccountName (pre-Windows 2000 Logon Name) as the external identity for Active Directory users. Please make sure this user has a valid samAccountName and try again. Learn more about troubleshooting Active Directory authentication at http://g.octopushq.com/TroubleshootingAD");
            }

            return userStore.CreateOrUpdate(
                username,
                displayName,
                emailAddress,
                externalId,
                null,
                true,
                null,
                false,
                new string[0]);
        }


        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LogonUser(
            string lpszUsername,
            string lpszDomain,
            string lpszPassword,
            int dwLogonType,
            int dwLogonProvider,
            out IntPtr phToken
            );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);
    }
}