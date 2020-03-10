using System.DirectoryServices.AccountManagement;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    interface IUserPrincipalFinder
    {
        IUserPrincipalWrapper FindByIdentity(PrincipalContext context, string samAccountName);
    }

    class UserPrincipalFinder : IUserPrincipalFinder
    {
        public IUserPrincipalWrapper FindByIdentity(PrincipalContext context, string samAccountName)
            => new UserPrincipalWrapper(UserPrincipal.FindByIdentity(context, samAccountName));
    }
}