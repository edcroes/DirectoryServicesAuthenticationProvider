using System;
using System.Globalization;
using Nancy;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Configuration;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;
using Octopus.Server.Extensibility.HostServices.Authentication;
using Octopus.Server.Extensibility.HostServices.Time;
using Octopus.Server.Extensibility.HostServices.Web;
using Octopus.Server.Extensibility.HostServices.Web.Commands;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.Web
{
    public class UserLoginAction : IApiAction
    {
        readonly IDirectoryServicesConfigurationStore configurationStore;
        readonly IDirectoryServicesCredentialValidator credentialValidator;
        readonly IAuthCookieCreator issuer;
        readonly IInvalidLoginTracker loginTracker;
        readonly ISleep sleep;
        readonly IApiActionModelBinder modelBinder;
        readonly IApiActionResponseCreator responseCreator;
        readonly IUserMapper userMapper;

        public UserLoginAction(
            IDirectoryServicesConfigurationStore configurationStore,
            IDirectoryServicesCredentialValidator credentialValidator, 
            IAuthCookieCreator issuer,
            IInvalidLoginTracker loginTracker,
            ISleep sleep,
            IApiActionModelBinder modelBinder,
            IApiActionResponseCreator responseCreator,
            IUserMapper userMapper)
        {
            this.configurationStore = configurationStore;
            this.credentialValidator = credentialValidator;
            this.issuer = issuer;
            this.loginTracker = loginTracker;
            this.sleep = sleep;
            this.modelBinder = modelBinder;
            this.responseCreator = responseCreator;
            this.userMapper = userMapper;
        }

        public Response Execute(NancyContext context, IResponseFormatter response)
        {
            if (!configurationStore.GetIsEnabled())
                return responseCreator.AsStatusCode(HttpStatusCode.BadRequest);

            var model = modelBinder.Bind<LoginCommand>(context);

            var attemptedUsername = model.Username;
            var requestUserHostAddress = context.Request.UserHostAddress;

            var action = loginTracker.BeforeAttempt(attemptedUsername, requestUserHostAddress);
            if (action == InvalidLoginAction.Ban)
            {
                return responseCreator.BadRequest("You have had too many failed login attempts in a short period of time. Please try again later.");
            }

            var userResult = credentialValidator.ValidateCredentials(attemptedUsername, model.Password);
            if (!userResult.Succeeded)
            {
                loginTracker.RecordFailure(attemptedUsername, requestUserHostAddress);

                if (action == InvalidLoginAction.Slow)
                {
                    sleep.For(1000);
                }

                return responseCreator.BadRequest(userResult.FailureReason);
            }

            var user = userResult.User;
            if (user == null || !user.IsActive || user.IsService)
            {
                loginTracker.RecordFailure(attemptedUsername, requestUserHostAddress);

                if (action == InvalidLoginAction.Slow)
                {
                    sleep.For(1000);
                }

                return responseCreator.BadRequest("Invalid username or password.");
            }

            loginTracker.RecordSucess(attemptedUsername, requestUserHostAddress);

            var cookie = issuer.CreateAuthCookie(context, user.IdentificationToken, model.RememberMe);

            return responseCreator.AsOctopusJson(response, userMapper.MapToResource(user))
                .WithCookie(cookie)
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Expires", DateTime.UtcNow.AddYears(1).ToString("R", DateTimeFormatInfo.InvariantInfo));
        }
    }
}