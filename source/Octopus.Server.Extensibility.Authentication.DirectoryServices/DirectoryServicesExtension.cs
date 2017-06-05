using Autofac;
using Octopus.Node.Extensibility.Authentication.Extensions;
using Octopus.Node.Extensibility.Extensions;
using Octopus.Node.Extensibility.Extensions.Infrastructure.Configuration;
using Octopus.Node.Extensibility.Extensions.Infrastructure.Web.Content;
using Octopus.Node.Extensibility.HostServices.Web;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Configuration;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Web;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices
{
    [OctopusPlugin("Directory Services", "Octopus Deploy")]
    public class DirectoryServicesExtension : IOctopusExtension
    {
        public void Load(ContainerBuilder builder)
        {
            builder.RegisterType<DirectoryServicesConfigurationMapping>().As<IConfigurationDocumentMapper>().InstancePerDependency();

            builder.RegisterType<DirectoryServicesConfigurationStore>()
                .As<IDirectoryServicesConfigurationStore>()
                .As<IAuthenticationSchemeProvider>()
                .As<IHasConfigurationSettings>()
                .InstancePerDependency();
            builder.RegisterType<DirectoryServicesConfigureCommands>()
                .As<IContributeToConfigureCommand>()
                .As<IHandleLegacyWebAuthenticationModeConfigurationCommand>()
                .InstancePerDependency();

            builder.RegisterType<DirectoryServicesUserCreationFromPrincipal>().As<ISupportsAutoUserCreationFromPrincipal>().InstancePerDependency();

            builder.RegisterType<DirectoryServicesContextProvider>().As<IDirectoryServicesContextProvider>().InstancePerDependency();
            builder.RegisterType<DirectoryServicesObjectNameNormalizer>().As<IDirectoryServicesObjectNameNormalizer>().InstancePerDependency();
            builder.RegisterType<DirectoryServicesExternalSecurityGroupLocator>().As<IDirectoryServicesExternalSecurityGroupLocator>().InstancePerDependency();

            builder.RegisterType<DirectoryServicesCredentialValidator>()
                .As<IDirectoryServicesCredentialValidator>()
                .As<IDoesBasicAuthentication>()
                .InstancePerDependency();

            builder.RegisterType<DirectoryServicesUserSecurityGroupExpiryChecker>().As<IDirectoryServicesUserSecurityGroupExpiryChecker>().InstancePerDependency();

            builder.RegisterType<DirectoryServicesGroupsChecker>()
                .As<IExternalGroupsChecker>()
                .InstancePerDependency();

            builder.RegisterType<DirectoryServicesHomeLinksContributor>().As<IHomeLinksContributor>().InstancePerDependency();

            builder.RegisterType<ListSecurityGroupsAction>().AsSelf().InstancePerDependency();

            builder.RegisterType<DirectoryServicesCSSContributor>().As<IContributesCSS>().InstancePerDependency();
            builder.RegisterType<DirectoryServicesStaticContentFolders>().As<IContributesStaticContentFolders>().InstancePerDependency();
            builder.RegisterType<DirectoryServicesJavascriptContributor>()
                .As<IContributesJavascript>()
                .As<IContributesAngularModules>()
                .InstancePerDependency();

            builder.RegisterType<DirectoryServicesAuthenticationProvider>()
                .As<IAuthenticationProvider>()
                .As<IAuthenticationProviderWithGroupSupport>()
                .AsSelf()
                .InstancePerDependency();
        }
    }
}