using System;
using System.Linq;
using System.Threading;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Configuration;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Identities;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Authentication.Resources.Identities;
using Octopus.Server.Extensibility.Authentication.Storage.User;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public class DirectoryServicesCredentialValidator : IDirectoryServicesCredentialValidator
    {
        readonly ILog log;
        readonly IDirectoryServicesObjectNameNormalizer objectNameNormalizer;
        readonly IUpdateableUserStore userStore;
        readonly IDirectoryServicesConfigurationStore configurationStore;
        readonly IIdentityCreator identityCreator;
        readonly IDirectoryServicesService directoryServicesService;

        internal static string EnvironmentUserDomainName = Environment.UserDomainName;

        public DirectoryServicesCredentialValidator(
            ILog log, 
            IDirectoryServicesObjectNameNormalizer objectNameNormalizer,
            IUpdateableUserStore userStore,
            IDirectoryServicesConfigurationStore configurationStore,
            IIdentityCreator identityCreator,
            IDirectoryServicesService directoryServicesService)
        {
            this.log = log;
            this.objectNameNormalizer = objectNameNormalizer;
            this.userStore = userStore;
            this.configurationStore = configurationStore;
            this.identityCreator = identityCreator;
            this.directoryServicesService = directoryServicesService;
        }

        public int Priority => 100;

        public AuthenticationUserCreateResult ValidateCredentials(string username, string password, CancellationToken cancellationToken)
        {
            if (!configurationStore.GetIsEnabled() || 
                !configurationStore.GetAllowFormsAuthenticationForDomainUsers())
            {
                return new AuthenticationUserCreateResult();
            }

            if (username == null) throw new ArgumentNullException(nameof(username));

            log.Verbose($"Validating credentials provided for '{username}'...");

            var validatedUser = directoryServicesService.ValidateCredentials(username, password, cancellationToken);
            if (!string.IsNullOrWhiteSpace(validatedUser.ValidationMessage))
            {
                return new AuthenticationUserCreateResult(validatedUser.ValidationMessage);
            }

            return GetOrCreateUser(validatedUser, validatedUser.UserPrincipalName, validatedUser.Domain, cancellationToken);
        }

        public AuthenticationUserCreateResult GetOrCreateUser(string username, CancellationToken cancellationToken)
        {
            var result = directoryServicesService.FindByIdentity(username);

            if (!string.IsNullOrWhiteSpace(result.ValidationMessage))
            {
                throw new ArgumentException(result.ValidationMessage);
            }

            return GetOrCreateUser(result, result.UserPrincipalName, result.Domain ?? EnvironmentUserDomainName, cancellationToken);
        }

        internal AuthenticationUserCreateResult GetOrCreateUser(UserValidationResult principal, string fallbackUsername, string fallbackDomain, CancellationToken cancellationToken)
        {
            var userPrincipalName = objectNameNormalizer.ValidatedUserPrincipalName(principal.UserPrincipalName, fallbackUsername, fallbackDomain);

            var samAccountName = principal.SamAccountName;
            if (!string.IsNullOrWhiteSpace(fallbackDomain) && !samAccountName.Contains("\\"))
            {
                samAccountName = fallbackDomain + @"\" + samAccountName;
            }

            var displayName = principal.DisplayName;
            var emailAddress = principal.EmailAddress;

            if (string.IsNullOrWhiteSpace(samAccountName))
            {
                log.Error($"We couldn't find a valid external identity to use for the Active Directory user '{displayName}' with email address '{emailAddress}' for the Octopus User Account named '{userPrincipalName}'. Octopus uses the samAccountName (pre-Windows 2000 Logon Name) as the external identity for Active Directory users. Please make sure this user has a valid samAccountName and try again. Learn more about troubleshooting Active Directory authentication at http://g.octopushq.com/TroubleshootingAD");
            }

            var authenticatingIdentity = identityCreator.Create(emailAddress, userPrincipalName, samAccountName, displayName);

            var users = userStore.GetByIdentity(authenticatingIdentity);

            var existingMatchingUser = users.SingleOrDefault(u => u.Identities != null && u.Identities.Any(identity => 
                identity.IdentityProviderName == DirectoryServicesAuthentication.ProviderName &&
                identity.Equals(authenticatingIdentity)));
            
            // if all identifiers match, nothing to see here, moving right along
            if (existingMatchingUser != null)
            {
                return new AuthenticationUserCreateResult(existingMatchingUser);
            }

            foreach (var user in users)
            {
                // if we haven't converted the old externalId into the new identity then set it up now
                var identity = user.Identities.FirstOrDefault(p => p.IdentityProviderName == DirectoryServicesAuthentication.ProviderName);
                if (identity == null)
                {
                    return new AuthenticationUserCreateResult(userStore.AddIdentity(user.Id, authenticatingIdentity, cancellationToken));
                }

                if (identity.Claims[IdentityCreator.SamAccountNameClaimType].Value != samAccountName &&
                    identity.Claims[IdentityCreator.UpnClaimType].Value != userPrincipalName)
                {
                    // we found a single other user in our DB that wasn't an exact match, but matched on some fields, so see if that user is still
                    // in AD
                    var otherUserPrincipal = directoryServicesService.FindByIdentity(identity.Claims[IdentityCreator.SamAccountNameClaimType].Value);

                    if (!otherUserPrincipal.Success)
                    {
                        // we couldn't find a match for the existing DB user's SamAccountName in AD, assume their details have been updated in AD
                        // and we need to modify the existing user in our DB.
                        identity.Claims[ClaimDescriptor.EmailClaimType].Value = emailAddress;
                        identity.Claims[IdentityCreator.UpnClaimType].Value = userPrincipalName;
                        identity.Claims[IdentityCreator.SamAccountNameClaimType].Value = samAccountName;
                        identity.Claims[ClaimDescriptor.DisplayNameClaimType].Value = displayName;

                        return new AuthenticationUserCreateResult(userStore.UpdateIdentity(user.Id, identity, cancellationToken));
                    }
                    
                    // otherUserPrincipal still exists in AD, so what we have here is a new user
                }
                else 
                {
                    // if we partially matched but the samAccountName or UPN is the same then this is the same user.
                    identity.Claims[IdentityCreator.UpnClaimType].Value = userPrincipalName;
                    identity.Claims[ClaimDescriptor.EmailClaimType].Value = emailAddress;
                    identity.Claims[IdentityCreator.SamAccountNameClaimType].Value = samAccountName;
                    identity.Claims[ClaimDescriptor.DisplayNameClaimType].Value = displayName;

                    return new AuthenticationUserCreateResult(userStore.UpdateIdentity(user.Id, identity, cancellationToken));
                }
            }

            if (!configurationStore.GetAllowAutoUserCreation())
                return new AuthenticationUserCreateResult("User could not be located and auto user creation is not enabled.");
            var userCreateResult = userStore.Create(
                userPrincipalName,
                displayName,
                emailAddress,
                cancellationToken,
                identities: new[] { authenticatingIdentity });

            return new AuthenticationUserCreateResult(userCreateResult);
        }
    }
}