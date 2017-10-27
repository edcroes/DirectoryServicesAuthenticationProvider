using System.ComponentModel;
using System.Net;
using Octopus.Data.Resources.Attributes;
using Octopus.Node.Extensibility.Extensions.Infrastructure.Configuration;

namespace Octopus.Node.Extensibility.Authentication.DirectoryServices.Configuration
{
    public class DirectoryServicesConfigurationResource : ExtensionConfigurationResource
    {

        public const string ActiveDirectoryContainerDescription = "Set the active directory container used for authentication.";

        public const string AuthenticationSchemeDescription = "When Domain authentication is used, specifies the scheme (Basic, Digest, IntegratedWindowsAuthentication, Negotiate, Ntlm).";

        public const string AllowFormsAuthenticationForDomainUsersDescription = "When Domain authentication is used, specifies whether the HTML-based username/password form can be used to sign in.";

        public const string AreSecurityGroupsEnabledDescription = "When Domain authentication is used, specifies whether to support security groups from AD.";

        public const string AllowAutoUserCreationDescription = "Whether unknown users will be automatically upon successful login.";

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