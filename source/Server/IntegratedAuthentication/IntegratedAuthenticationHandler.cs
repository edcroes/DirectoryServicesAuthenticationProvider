using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using Octopus.Data.Storage.User;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Authentication.Resources;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.IntegratedAuthentication
{
    class IntegratedAuthenticationHandler : IIntegratedAuthenticationHandler
    {
        readonly ILog log;
        readonly IAuthCookieCreator tokenIssuer;
        readonly IAuthenticationConfigurationStore authenticationConfigurationStore;
        readonly DirectoryServicesUserCreationFromPrincipal supportsAutoUserCreationFromPrincipals;
        readonly IUserStore userStore;

        public IntegratedAuthenticationHandler(ILog log, 
            IAuthCookieCreator tokenIssuer,
            IAuthenticationConfigurationStore authenticationConfigurationStore, 
            DirectoryServicesUserCreationFromPrincipal supportsAutoUserCreationFromPrincipals,
            IUserStore userStore)
        {
            this.log = log;
            this.tokenIssuer = tokenIssuer;
            this.authenticationConfigurationStore = authenticationConfigurationStore;
            this.supportsAutoUserCreationFromPrincipals = supportsAutoUserCreationFromPrincipals;
            this.userStore = userStore;
        }

        public Task HandleRequest(HttpContext context)
        {
            var result = TryAuthenticateRequest(context);
            
            var principal = result.User;

            // Decode the state object sent from the client (if there was one) so we can use those hints to build the most appropriate response
            // If the state can't be interpreted, we will fall back to a safe-by-default behaviour, however:
            //   1. Deep-links will not work because we don't know where the anonymous request originally wanted to go
            //   2. Cookies may not have the Secure flag set properly when SSL Offloading is in play
            LoginState state = null;
            if (context.Request.Query.TryGetValue("state", out var stateString))
            {
                try
                {
                    state = JsonConvert.DeserializeObject<LoginState>(stateString.FirstOrDefault());
                }
                catch (Exception e)
                {
                    log.Warn(e, "Invalid login state object passed to the server when setting up the NTLM challenge. Falling back to the default behaviour.");
                }
            }

            // Build the auth cookies to send back with the response
            var authCookies = tokenIssuer.CreateAuthCookies(principal.IdentificationToken, SessionExpiry.TwentyDays, context.Request.IsHttps, state?.UsingSecureConnection);

            // If the caller has provided a redirect after successful login, we need to check it is a local address - preventing Open Redirection attacks
            if (!string.IsNullOrWhiteSpace(state?.RedirectAfterLoginTo))
            {
                var whitelist = authenticationConfigurationStore.GetTrustedRedirectUrls();
                var redirectAfterLoginTo = state.RedirectAfterLoginTo.Replace(DirectoryServicesConstants.IntegratedAuthVirtualDirectory, string.Empty);
                if (Requests.IsLocalUrl(redirectAfterLoginTo, whitelist))
                {
                    // This is a safe redirect, let's go!
                    context.Response.Redirect(redirectAfterLoginTo);
                    foreach (var cookie in authCookies)
                    {
                        context.Response.Cookies.Append(cookie.Name, cookie.Value);
                    }
                    return Task.CompletedTask;
                }

                // Just log that we detected a non-local redirect URL, and fall through to the root of the local web site
                log.WarnFormat(
                    "Prevented potential Open Redirection attack on an NTLM challenge, to the non-local url {0}",
                    redirectAfterLoginTo);
            }

            // By default, redirect to the root of the local web site
            context.Response.Redirect(context.Request.PathBase.Value ?? "/");
            foreach (var cookie in authCookies)
            {
                context.Response.Cookies.Append(cookie.Name, cookie.Value);
            }
            
            return Task.CompletedTask;
        }
        
        OctopusAuthenticationResult TryAuthenticateRequest(HttpContext context)
        {
            if (context == null) throw new ArgumentNullException(nameof(context));
            if (context.Request == null) throw new ArgumentNullException($"{nameof(context)}.{nameof(context.Request)}");
            
            // If there is no "RequestPrincipal" in the Context.Items it's not our job to authenticate this request
            var principal = context.User;
            if (string.IsNullOrWhiteSpace(principal.Identity.Name))
                return OctopusAuthenticationResult.Anonymous;

            using (var cts = new CancellationTokenSource(TimeSpan.FromMinutes(1)))
            {
                // Attempt to create the user based on the provided System.Security.Principal.IPrincipal
                var userResult = supportsAutoUserCreationFromPrincipals.GetOrCreateUser(principal, cts.Token);

                // If we couldn't create the user account we also can't authenticate this request
                if (userResult == null || !userResult.Succeeded) return OctopusAuthenticationResult.Anonymous;

                // Otherwise we should be good to go!
                var user = userStore.GetByIdentificationToken(userResult.User.IdentificationToken);

                return user == null
                    ? OctopusAuthenticationResult.Anonymous
                    : OctopusAuthenticationResult.Authenticated(user);
            }
        }

    }
}