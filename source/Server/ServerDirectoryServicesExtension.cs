using Autofac;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Configuration;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Web;
using Octopus.Server.Extensibility.Authentication.Extensions;
using Octopus.Server.Extensibility.Authentication.Extensions.Identities;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Content;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices
{
    public class ServerDirectoryServicesExtension : DirectoryServicesExtension
    {
        public override void Load(ContainerBuilder builder)
        {
            base.Load(builder);

            builder.RegisterType<DirectoryServicesConfigureCommands>()
                .As<IContributeToConfigureCommand>()
                .InstancePerDependency();
            
            builder.RegisterType<DirectoryServicesStaticContentFolders>().As<IContributesStaticContentFolders>().InstancePerDependency();

            builder.RegisterType<ListSecurityGroupsAction>().AsSelf().InstancePerDependency();
            builder.RegisterType<UserLookupAction>().AsSelf().InstancePerDependency();

            builder.RegisterType<DirectoryServicesAuthenticationProvider>()
                .As<IAuthenticationProvider>()
                .As<IAuthenticationProviderWithGroupSupport>()
                .As<IContributesCSS>()
                .As<IContributesJavascript>()
                .As<IUseAuthenticationIdentities>()
                .AsSelf()
                .InstancePerDependency();
        }
    }
}