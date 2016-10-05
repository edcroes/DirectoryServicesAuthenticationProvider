using System;
using System.ComponentModel;
using System.DirectoryServices.AccountManagement;
using System.Runtime.InteropServices;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Configuration;
using Octopus.Server.Extensibility.HostServices.Diagnostics;
using Octopus.Server.Extensibility.HostServices.Model;

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
        readonly IDirectoryServicesCredentialNormalizer credentialNormalizer;
        readonly IDirectoryServicesContextProvider contextProvider;
        readonly IUserStore userStore;
        readonly IDirectoryServicesConfigurationStore configurationStore;

        public DirectoryServicesCredentialValidator(
            ILog log, 
            IDirectoryServicesCredentialNormalizer credentialNormalizer,
            IDirectoryServicesContextProvider contextProvider,
            IUserStore userStore,
            IDirectoryServicesConfigurationStore configurationStore)
        {
            this.log = log;
            this.credentialNormalizer = credentialNormalizer;
            this.contextProvider = contextProvider;
            this.userStore = userStore;
            this.configurationStore = configurationStore;
        }

        public UserCreateOrUpdateResult ValidateCredentials(string username, string password)
        {
            if (!configurationStore.GetIsEnabled() || 
                !configurationStore.GetAllowFormsAuthenticationForDomainUsers())
            {
                return null;
            }

            if (username == null) throw new ArgumentNullException("username");

            log.Verbose($"Validating credentials provided for '{username}'...");

            string domain;
            credentialNormalizer.NormalizeCredentials(username, out username, out domain);

            using (var context = contextProvider.GetContext(domain))
            {
                var principal = UserPrincipal.FindByIdentity(context, username);

                if (principal == null)
                {
                    var searchedContext = domain ?? context.Name ?? context.ConnectedServer;
                    log.Info($"A principal identifiable by '{username}' was not found in '{searchedContext}'");
                    return null;
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

                        return null;
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
            credentialNormalizer.NormalizeCredentials(username, out username, out domain);

            using (var context = contextProvider.GetContext(domain))
            {
                var principal = UserPrincipal.FindByIdentity(context, username);
                if (principal == null)
                {
                    var searchedContext = domain ?? context.Name ?? context.ConnectedServer;
                    throw new ArgumentException(string.Format("A principal identifiable by '{0}' was not found in '{1}'", username, searchedContext));
                }

                return GetOrCreateUser(principal, username, domain ?? Environment.UserDomainName);
            }
        }

        UserCreateOrUpdateResult GetOrCreateUser(UserPrincipal principal, string fallbackUsername, string fallbackDomain)
        {
            var name = credentialNormalizer.ValidatedUserPrincipalName(principal, fallbackUsername, fallbackDomain);

            return userStore.GetOrCreateUser(
                name,
                string.IsNullOrWhiteSpace(principal.DisplayName) ? principal.Name : principal.DisplayName,
                principal.EmailAddress,
                principal.SamAccountName);
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