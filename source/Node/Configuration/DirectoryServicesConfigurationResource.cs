using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Net;
using Octopus.Data.Resources.Attributes;
using Octopus.Node.Extensibility.Extensions.Infrastructure.Configuration;

namespace Octopus.Node.Extensibility.Authentication.DirectoryServices.Configuration
{
    public class DirectoryServicesConfigurationResource : ExtensionConfigurationResource
    {

        public const string ActiveDirectoryContainerDescription = "Comma-separated whitelist of domains that are allowed to retrieve data (empty turns CORS off, * allows all).";

        public const string AuthenticationSchemeDescription = "Comma-separated whitelist of domains that are allowed to retrieve data (empty turns CORS off, * allows all).";

        public const string AllowFormsAuthenticationForDomainUsersDescription = "Comma-separated whitelist of domains that are allowed to retrieve data (empty turns CORS off, * allows all).";

        public const string AreSecurityGroupsEnabledDescription = "Comma-separated whitelist of domains that are allowed to retrieve data (empty turns CORS off, * allows all).";

        public const string AllowAutoUserCreationDescription = "Comma-separated whitelist of domains that are allowed to retrieve data (empty turns CORS off, * allows all).";

        [DisplayName("Active Directory Container")]
        [Description(ActiveDirectoryContainerDescription)]
        [Writeable]
        public string ActiveDirectoryContainer { get; set; }

        [DisplayName("Authentication Scheme")]
        [Description(AuthenticationSchemeDescription)]
        [Writeable]
        public AuthenticationSchemes AuthenticationScheme { get; set; }

        [DisplayName("Allow Forms Authentication For Domain Users")]
        [Description(AllowFormsAuthenticationForDomainUsersDescription)]
        [Writeable]
        public bool AllowFormsAuthenticationForDomainUsers { get; set; }

        [DisplayName("Security Groups Enabled")]
        [Description(AreSecurityGroupsEnabledDescription)]
        [Writeable]
        public bool AreSecurityGroupsEnabled { get; set; }

        [DisplayName("Allow Auto User Creation")]
        [Description(AllowAutoUserCreationDescription)]
        [Writeable]
        public bool? AllowAutoUserCreation { get; set; }
    }
}