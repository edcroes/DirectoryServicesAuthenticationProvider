using System;
using System.Linq;
using System.Net;
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
        readonly IIntegratedChallengeTracker integratedChallengeTracker;

        public IntegratedAuthenticationHandler(ILog log,
            IAuthCookieCreator tokenIssuer,
            IAuthenticationConfigurationStore authenticationConfigurationStore, 
            DirectoryServicesUserCreationFromPrincipal supportsAutoUserCreationFromPrincipals,
            IUserStore userStore,
            IIntegratedChallengeTracker integratedChallengeTracker)
        {
            this.log = log;
            this.tokenIssuer = tokenIssuer;
            this.authenticationConfigurationStore = authenticationConfigurationStore;
            this.supportsAutoUserCreationFromPrincipals = supportsAutoUserCreationFromPrincipals;
            this.userStore = userStore;
            this.integratedChallengeTracker = integratedChallengeTracker;
        }

        public Task HandleRequest(HttpContext context)
        {
            var state = GetLoginState(context);

            // Based on https://github.com/dotnet/runtime/blob/cf63e732fc6fb57c0ea97c1b4ca965acce46343a/src/libraries/System.Net.Security/src/System/Net/Security/NegotiateStreamPal.Windows.cs#L52
            // we're being a bit cautious about using IsAuthenticated
            if (string.IsNullOrWhiteSpace(context.User.Identity.Name))
            {
                if (integratedChallengeTracker.IsConnectionKnown(context.Connection.Id))
                {
                    // if we've seen this connection before and the user still isn't set then something has gone
                    // wrong with the challenge. Most likely due to cross domains now we're NETCore, https://github.com/OctopusDeploy/Issues/issues/6265
                    var stateRedirectAfterLoginTo = state.RedirectAfterLoginTo;

                    // this matches an error structure that the portal currently uses. It is not something the server it
                    // currently knows directly about. We may make it a 1st error object at some point to help consistency.
                    var errorObj = new
                    {
                        ErrorMessage = "Authentication Error",
                        Errors = new [] {"An error occurred with Windows authentication, possibly due to a known issue, please try using forms authentication."},
                        DetailLinks = new[] {"https://g.octopushq.com/TroubleshootingAD#Integrated"}
                    };
                    
                    // we used to use the query string to pass errors back to the portal but that was quite problematic when it came to not interfering
                    // with deep links etc. The portal sign in page now checks for this cookie to see if an external 
                    // auth provider is trying to return an error.
                    context.Response.Cookies.Append("Octopus-Error", JsonConvert.SerializeObject(errorObj), new CookieOptions { MaxAge = TimeSpan.FromSeconds(15) });
                    
                    // we pass back to the original link here (e.g. the deep link that originally triggered the sign in)
                    // we normally wouldn't do this without the user being authenticated, but given we know they aren't
                    // authenticated we'll redirect back and rely on the sign in page kicking in again and seeing the cookie.
                    context.Response.Redirect(stateRedirectAfterLoginTo);
                    
                    // count this as complete, if the browser comes back on the same connection we'll start over 
                    integratedChallengeTracker.SetConnectionChallengeCompleted(context.Connection.Id);
                }
                else
                {
                    context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                    integratedChallengeTracker.SetConnectionChallengeInitiated(context.Connection.Id);
                }
                return Task.CompletedTask;
            }

            if (integratedChallengeTracker.IsConnectionKnown(context.Connection.Id))
            {
                integratedChallengeTracker.SetConnectionChallengeCompleted(context.Connection.Id);
            }

            var result = TryAuthenticateRequest(context);
            
            var principal = result.User;

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

        LoginState GetLoginState(HttpContext context)
        {
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

            return state;
        }

        OctopusAuthenticationResult TryAuthenticateRequest(HttpContext context)
        {
            if (context == null) throw new ArgumentNullException(nameof(context));
            if (context.Request == null) throw new ArgumentNullException($"{nameof(context)}.{nameof(context.Request)}");
            
            // If there is no "RequestPrincipal" in the Context.Items it's not our job to authenticate this request
            var principal = context.User;
            if (string.IsNullOrWhiteSpace(principal.Identity.Name))
                return OctopusAuthenticationResult.Anonymous;

            using (var cts = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted, new CancellationTokenSource(TimeSpan.FromMinutes(1)).Token))
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