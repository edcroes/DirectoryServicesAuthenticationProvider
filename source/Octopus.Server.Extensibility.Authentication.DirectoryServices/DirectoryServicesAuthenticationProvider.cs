using System.Collections.Generic;
using System.Linq;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Configuration;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices;
using Octopus.Server.Extensibility.Authentication.Extensions;
using Octopus.Server.Extensibility.Authentication.Resources;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Content;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices
{
    public class DirectoryServicesAuthenticationProvider : 
        IAuthenticationProviderWithGroupSupport,
        IContributesCSS,
        IContributesJavascript
    {
        readonly IDirectoryServicesConfigurationStore configurationStore;

        public DirectoryServicesAuthenticationProvider(IDirectoryServicesConfigurationStore configurationStore)
        {
            this.configurationStore = configurationStore;
        }

        public string IdentityProviderName => "Active Directory";

        public bool IsEnabled => configurationStore.GetIsEnabled();

        public bool SupportsPasswordManagement => false;

        string ChallengeUri => DirectoryServicesConstants.ChallengePath;

        public AuthenticationProviderElement GetAuthenticationProviderElement()
        {
            var authenticationProviderElement = new AuthenticationProviderElement
            {
                Name = IdentityProviderName,
                FormsLoginEnabled = configurationStore.GetAllowFormsAuthenticationForDomainUsers(),
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

        public IEnumerable<string> GetCSSUris()
        {
            return !configurationStore.GetIsEnabled()
                ? Enumerable.Empty<string>()
                : new[] { "~/styles/directoryServices.css" };
        }

        public IEnumerable<string> GetJavascriptUris()
        {
            return !configurationStore.GetIsEnabled()
                ? Enumerable.Empty<string>()
                : new[] { "~/areas/users/ad_auth_provider.js" };
        }
    }
}