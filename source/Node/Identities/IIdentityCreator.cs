using Octopus.Data.Model.User;

namespace Octopus.Node.Extensibility.Authentication.DirectoryServices.Identities
{
    public interface IIdentityCreator
    {
        Identity Create(string email, string upn, string samAccountName, string displayName);
    }
}