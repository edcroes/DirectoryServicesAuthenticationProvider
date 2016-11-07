using Octopus.Server.Extensibility.Authentication.DirectoryServices.Configuration;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices;
using Octopus.Server.Extensibility.Authentication.Extensions;
using Octopus.Server.Extensibility.Authentication.Resources;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices
{
    public class DirectoryServicesAuthenticationProvider : IAuthenticationProviderWithGroupSupport
    {
        readonly IDirectoryServicesConfigurationStore configurationStore;

        public DirectoryServicesAuthenticationProvider(IDirectoryServicesConfigurationStore configurationStore)
        {
            this.configurationStore = configurationStore;
        }

        public string IdentityProviderName => "Active Directory";

        public bool IsEnabled => configurationStore.GetIsEnabled();

        public bool SupportsPasswordManagement => false;

        public string AuthenticateUri => DirectoryServicesApi.ApiUsersAuthenticate;
        string ChallengeUri => DirectoryServicesConstants.ChallengePath;

        string LinkHtml(string requestDirectoryPath)
        {
            return $"<a href='{{{{authenticateLink}}}}'><div class=\"external-provider-button ds-button\"><img src=\"{requestDirectoryPath}/images/directory_services_signin_buttons/microsoft-logo.svg\"><div>Sign in with a domain account</div></div></a>";
        }

        public AuthenticationProviderElement GetAuthenticationProviderElement(string requestDirectoryPath)
        {
            var authenticationProviderElement = new AuthenticationProviderElement
            {
                Name = IdentityProviderName,
                FormsLoginEnabled = configurationStore.GetAllowFormsAuthenticationForDomainUsers(),
                FormsUsernameIdentifier = @"\",
                LinkHtml = LinkHtml(requestDirectoryPath)
            };
            authenticationProviderElement.Links.Add(AuthenticationProviderElement.FormsAuthenticateLinkName, "~" + AuthenticateUri);
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
                LookupUri = DirectoryServicesApi.ApiExternalGroupsLookup
            };
        }
    }
}