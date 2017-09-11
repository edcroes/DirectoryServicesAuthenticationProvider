using Autofac;
using Octopus.Node.Extensibility.Authentication.DirectoryServices;
using Octopus.Node.Extensibility.Authentication.Extensions;
using Octopus.Node.Extensibility.Extensions.Infrastructure.Configuration;
using Octopus.Node.Extensibility.Extensions.Infrastructure.Web.Content;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Configuration;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Web;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices
{
    public class ServerDirectoryServicesExtension : DirectoryServicesExtension
    {
        public override void Load(ContainerBuilder builder)
        {
            base.Load(builder);

            builder.RegisterType<DirectoryServicesConfigureCommands>()
                .As<IContributeToConfigureCommand>()
                .As<IHandleLegacyWebAuthenticationModeConfigurationCommand>()
                .InstancePerDependency();
            
            builder.RegisterType<DirectoryServicesStaticContentFolders>().As<IContributesStaticContentFolders>().InstancePerDependency();

            builder.RegisterType<ListSecurityGroupsAction>().AsSelf().InstancePerDependency();
            builder.RegisterType<UserLookupAction>().AsSelf().InstancePerDependency();

            builder.RegisterType<DirectoryServicesAuthenticationProvider>()
                .As<IAuthenticationProvider>()
                .As<IAuthenticationProviderWithGroupSupport>()
                .As<IContributesCSS>()
                .As<IContributesJavascript>()
                .AsSelf()
                .InstancePerDependency();
        }
    }
}