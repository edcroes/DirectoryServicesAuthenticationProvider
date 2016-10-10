using Octopus.Server.Extensibility.Authentication.DirectoryServices.Configuration;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices;
using Octopus.Server.Extensibility.Extensions.Contracts.Authentication;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Resources;

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

        string LinkHtml()
        {
            if (configurationStore.GetAllowFormsAuthenticationForDomainUsers())
            {
                return "<div class=\"text-center margin-top-20\">Or, <a href=\"{{authenticateLink}}\"> sign in with your Microsoft Windows domain account</a></div>";
            }
            return "<div class=\"text-center\"><a href=\"{{authenticateLink}}\">Sign in with your Microsoft Windows domain account <i class=\"fa fa-arrow-circle-right\"></i></a></div>";
        }

        public AuthenticationProviderElement GetAuthenticationProviderElement(string siteBaseUri)
        {
            var authenticationProviderElement = new AuthenticationProviderElement
            {
                Name = IdentityProviderName,
                FormsLoginEnabled = configurationStore.GetAllowFormsAuthenticationForDomainUsers(),
                FormsUsernameIdentifier = @"\",
                LinkHtml = LinkHtml()
            };
            authenticationProviderElement.Links.Add(AuthenticationProviderElement.FormsAuthenticateLinkName, AuthenticateUri);
            authenticationProviderElement.Links.Add(AuthenticationProviderElement.AuthenticateLinkName, ChallengeUri);
            return authenticationProviderElement;
        }

        public AuthenticationProviderThatSupportsGroups GetGroupLookupElement()
        {
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