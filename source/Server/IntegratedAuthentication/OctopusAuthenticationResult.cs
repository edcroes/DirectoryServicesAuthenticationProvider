using Microsoft.AspNetCore.Http;
using Octopus.Data.Model.User;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.IntegratedAuthentication
{
    public class OctopusAuthenticationResult
    {
        OctopusAuthenticationResult(IUser user, HttpResponse rejectionResponse)
        {
            User = user;
            RejectionResponse = rejectionResponse;
        }

        public IUser User { get; }
        public HttpResponse RejectionResponse { get; }
            
        public bool IsAnonymous => User == null && RejectionResponse == null;

        public static readonly OctopusAuthenticationResult Anonymous = new OctopusAuthenticationResult(null, null);

        public static OctopusAuthenticationResult Authenticated(IUser user)
        {
            return new OctopusAuthenticationResult(user, null);
        }

        public static OctopusAuthenticationResult Rejected(HttpResponse rejectionResponse)
        {
            return new OctopusAuthenticationResult(null, rejectionResponse);
        }
    }
}