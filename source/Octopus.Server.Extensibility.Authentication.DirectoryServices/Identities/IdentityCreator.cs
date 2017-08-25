using Octopus.Data.Model.User;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.Identities
{
    public class IdentityCreator : IIdentityCreator
    {
        public const string EmailClaimType = "email";
        public const string UpnClaimType = "upn";
        public const string SamAccountNameClaimType = "sam";
        public const string DisplayNameClaimType = "dn";

        public Identity Create(string email, string upn, string samAccountName, string displayName)
        {
            return new Identity(DirectoryServicesAuthenticationProvider.ProviderName)
                .WithClaim(EmailClaimType, email, true)
                .WithClaim(UpnClaimType, upn, true)
                .WithClaim(SamAccountNameClaimType, samAccountName, true)
                .WithClaim(DisplayNameClaimType, displayName, false);
        }
    }
}