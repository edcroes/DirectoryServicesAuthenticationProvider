using System.Net;
using Octopus.Server.Extensibility.HostServices.Model;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.Configuration
{
    public class DirectoryServicesConfiguration : IId
    {
        public string Id { get; set; }

        public bool IsEnabled { get; set; }

        /// <summary>
        /// Gets or sets the active directory container, if not specified default container is used
        /// </summary>
        public string ActiveDirectoryContainer { get; set; }

        /// <summary>
        /// Gets or sets the authentication scheme to use when authentication Domain users.
        /// </summary>
        public AuthenticationSchemes AuthenticationScheme { get; set; }

        /// <summary>
        /// Gets or sets the when the HTML-based username/password form will be presented for domain users. Defaults to true. 
        /// </summary>
        public bool AllowFormsAuthenticationForDomainUsers { get; set; }
    }
}