using Octopus.Data.Model;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Configuration;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Identities;
using Octopus.Server.Extensibility.Authentication.Extensions;
using Octopus.Server.Extensibility.Authentication.Extensions.Identities;
using Octopus.Server.Extensibility.Authentication.Resources;
using Octopus.Server.Extensibility.Authentication.Resources.Identities;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices
{
    public class DirectoryServicesAuthenticationProvider : IAuthenticationProviderWithGroupSupport, IUseAuthenticationIdentities
    {
        public const string ProviderName = "Active Directory";

        readonly IDirectoryServicesConfigurationStore configurationStore;

        public DirectoryServicesAuthenticationProvider(IDirectoryServicesConfigurationStore configurationStore)
        {
            this.configurationStore = configurationStore;
        }

        public string IdentityProviderName => ProviderName;

        public bool IsEnabled => configurationStore.GetIsEnabled();

        public bool SupportsPasswordManagement => false;

        string ChallengeUri => DirectoryServicesConstants.ChallengePath;

        string LinkHtml()
        {
            return "<active-directory-auth-provider provider='provider' should-auto-login='shouldAutoLogin' is-submitting='isSubmitting' handle-sign-in-error='handleSignInError'></active-directory-auth-provider>";
        }

        public AuthenticationProviderElement GetAuthenticationProviderElement()
        {
            var authenticationProviderElement = new AuthenticationProviderElement
            {
                Name = IdentityProviderName,
                FormsLoginEnabled = configurationStore.GetAllowFormsAuthenticationForDomainUsers(),
                LinkHtml = LinkHtml()
            };
            authenticationProviderElement.Links.Add(AuthenticationProviderElement.AuthenticateLinkName, "~" + ChallengeUri);
            return authenticationProviderElement;
        }

        public AuthenticationProviderThatSupportsGroups GetGroupLookupElement()
        {
            if (!configurationStore.GetAreSecurityGroupsEnabled())
                return null;
            return new AuthenticationProviderThatSupportsGroups
            {
                Name = IdentityProviderName,
                IsRoleBased = false,
                SupportsGroupLookup = true,
                LookupUri = "~" + DirectoryServicesApi.ApiExternalGroupsLookup
            };
        }

        public string[] GetAuthenticationUrls()
        {
            return new string[0];
        }

        public IdentityMetadataResource GetMetadata()
        {
            return new IdentityMetadataResource
            {
                ProviderName = ProviderName,
                ClaimDescriptors = new []
                {
                    new ClaimDescriptor { Type = ClaimDescriptor.DisplayNameClaimType, Label = "Display name", IsIdentifyingClaim = false}, 
                    new ClaimDescriptor { Type = IdentityCreator.UpnClaimType, Label = "User principal name", IsIdentifyingClaim = true}, 
                    new ClaimDescriptor { Type = IdentityCreator.SamAccountNameClaimType, Label = "Sam Account Name", IsIdentifyingClaim = true},
                    new ClaimDescriptor { Type = ClaimDescriptor.EmailClaimType, Label = "Email address", IsIdentifyingClaim = true}
                },
                Links = new LinkCollection().Add("UserLookup", "~" + DirectoryServicesApi.ApiExternalUsersLookup)
            };
        }
    }
}