using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public interface IUserPrincipalWrapper : IPrincipalWrapper
    {
        IEnumerable<IPrincipalWrapper> GetAuthorizationGroups();
        IEnumerable<IPrincipalWrapper> GetGroups();
    }

    public class UserPrincipalWrapper : PrincipalWrapper, IUserPrincipalWrapper
    {
        readonly UserPrincipal userPrincipal;

        public UserPrincipalWrapper(UserPrincipal userPrincipal)
            : base(userPrincipal)
        {
            this.userPrincipal = userPrincipal;
        }

        public IEnumerable<IPrincipalWrapper> GetAuthorizationGroups()
            => userPrincipal.GetAuthorizationGroups().Select(p => new PrincipalWrapper(p));

        public IEnumerable<IPrincipalWrapper> GetGroups()
            => userPrincipal.GetGroups().Select(p => new PrincipalWrapper(p));
    }
}