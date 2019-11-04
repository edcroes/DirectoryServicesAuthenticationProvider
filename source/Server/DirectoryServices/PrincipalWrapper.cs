
using System.DirectoryServices.AccountManagement;
using System.Security.Principal;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    public interface IPrincipalWrapper
    {
        SecurityIdentifier Sid { get; }
    }
    
    public class PrincipalWrapper : IPrincipalWrapper
    {
        readonly Principal principal;

        public PrincipalWrapper(Principal principal)
        {
            this.principal = principal;
        }

        public SecurityIdentifier Sid => principal.Sid;
    }
}