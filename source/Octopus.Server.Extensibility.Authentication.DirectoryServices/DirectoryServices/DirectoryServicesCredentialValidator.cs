using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Runtime.InteropServices;
using Octopus.Data.Model.User;
using Octopus.Data.Storage.User;
using Octopus.Diagnostics;
using Octopus.Node.Extensibility.Authentication.HostServices;
using Octopus.Node.Extensibility.Authentication.Storage.User;
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
        readonly IUpdateableUserStore userStore;
        readonly IDirectoryServicesConfigurationStore configurationStore;

        public DirectoryServicesCredentialValidator(
            ILog log, 
            IDirectoryServicesObjectNameNormalizer objectNameNormalizer,
            IDirectoryServicesContextProvider contextProvider,
            IUpdateableUserStore userStore,
            IDirectoryServicesConfigurationStore configurationStore)
        {
            this.log = log;
            this.objectNameNormalizer = objectNameNormalizer;
            this.contextProvider = contextProvider;
            this.userStore = userStore;
            this.configurationStore = configurationStore;
        }

        public int Priority => 100;

        public AuthenticationUserCreateResult ValidateCredentials(string username, string password)
        {
            if (!configurationStore.GetIsEnabled() || 
                !configurationStore.GetAllowFormsAuthenticationForDomainUsers())
            {
                return new AuthenticationUserCreateResult();
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
                        return new AuthenticationUserCreateResult("Username not found.  UPN format may not be supported for your domain configuration.");
                    }
                    return new AuthenticationUserCreateResult("Username not found");
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

                        return new AuthenticationUserCreateResult("Active directory login error");
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

        public AuthenticationUserCreateResult GetOrCreateUser(string username)
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

        AuthenticationUserCreateResult GetOrCreateUser(UserPrincipal principal, string fallbackUsername, string fallbackDomain)
        {
            var userPrincipalName = objectNameNormalizer.ValidatedUserPrincipalName(principal, fallbackUsername, fallbackDomain);

            var samAccountName = principal.SamAccountName;
            if (!string.IsNullOrWhiteSpace(fallbackDomain))
            {
                samAccountName = fallbackDomain + @"\" + samAccountName;
            }

            var displayName = string.IsNullOrWhiteSpace(principal.DisplayName) ? principal.Name : principal.DisplayName;
            var emailAddress = principal.EmailAddress;

            if (string.IsNullOrWhiteSpace(samAccountName))
            {
                log.Error($"We couldn't find a valid external identity to use for the Active Directory user '{displayName}' with email address '{emailAddress}' for the Octopus User Account named '{userPrincipalName}'. Octopus uses the samAccountName (pre-Windows 2000 Logon Name) as the external identity for Active Directory users. Please make sure this user has a valid samAccountName and try again. Learn more about troubleshooting Active Directory authentication at http://g.octopushq.com/TroubleshootingAD");
            }

            var user = userStore.GetByIdentity(new ActiveDirectoryIdentityToMatch(DirectoryServicesAuthenticationProvider.ProviderName, emailAddress, userPrincipalName, samAccountName));

            if (user != null)
            {
                // if we haven't converted the old externalId into the new identity then set it up now
                if (!user.Identities.OfType<ActiveDirectoryIdentity>().Any())
                {
                    user = userStore.AddIdentity(user.Id, NewIdentity((user.Identities.Max(x => int.Parse(x.Id)) + 1).ToString(), emailAddress, userPrincipalName, samAccountName));
                }
                
                return new AuthenticationUserCreateResult(user);
            }

            if (!configurationStore.GetAllowAutoUserCreation())
                return new AuthenticationUserCreateResult("User could not be located and auto user creation is not enabled.");
            
            var userCreateResult = userStore.Create(
                userPrincipalName,
                displayName,
                emailAddress,
                identity: NewIdentity("1",
                    emailAddress,
                    userPrincipalName,
                    samAccountName),
                isService: false);

            return new AuthenticationUserCreateResult (userCreateResult);
        }

        Identity NewIdentity(string id, string emailAddress, string userPrincipalName, string samAccountName)
        {
            return new ActiveDirectoryIdentity(
                id,
                DirectoryServicesAuthenticationProvider.ProviderName,
                emailAddress,
                userPrincipalName,
                samAccountName);
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