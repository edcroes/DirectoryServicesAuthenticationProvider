using Octopus.Data.Model.User;
using Octopus.Node.Extensibility.Authentication.Resources.Identities;

namespace Octopus.Node.Extensibility.Authentication.DirectoryServices.Identities
{
    public class IdentityCreator : IIdentityCreator
    {
        public const string UpnClaimType = "upn";
        public const string SamAccountNameClaimType = "sam";

        public Identity Create(string email, string upn, string samAccountName, string displayName)
        {
            return new Identity(DirectoryServicesAuthentication.ProviderName)
                .WithClaim(ClaimDescriptor.EmailClaimType, email, true)
                .WithClaim(UpnClaimType, upn, true)
                .WithClaim(SamAccountNameClaimType, samAccountName, true)
                .WithClaim(ClaimDescriptor.DisplayNameClaimType, displayName, false);
        }
    }
}