using Autofac;
using Octopus.Node.Extensibility.Authentication.DirectoryServices.Configuration;
using Octopus.Node.Extensibility.Authentication.DirectoryServices.DirectoryServices;
using Octopus.Node.Extensibility.Authentication.DirectoryServices.Identities;
using Octopus.Node.Extensibility.Authentication.Extensions;
using Octopus.Node.Extensibility.Extensions;
using Octopus.Node.Extensibility.Extensions.Infrastructure;
using Octopus.Node.Extensibility.Extensions.Infrastructure.Configuration;
using Octopus.Node.Extensibility.Extensions.Mappings;
using Octopus.Node.Extensibility.HostServices.Web;

namespace Octopus.Node.Extensibility.Authentication.DirectoryServices
{
    [OctopusPlugin("Directory Services", "Octopus Deploy")]
    public abstract class DirectoryServicesExtension : IOctopusExtension
    {
        public virtual void Load(ContainerBuilder builder)
        {
            builder.RegisterType<DirectoryServicesConfigurationMapping>().As<IConfigurationDocumentMapper>().InstancePerDependency();

            builder.RegisterType<DatabaseInitializer>().As<IExecuteWhenDatabaseInitializes>().InstancePerDependency();

            builder.RegisterType<IdentityCreator>().As<IIdentityCreator>().SingleInstance();

            builder.RegisterType<DirectoryServicesConfigurationStore>()
                .As<IDirectoryServicesConfigurationStore>()
                .As<IAuthenticationSchemeProvider>()
                .InstancePerDependency();

            builder.RegisterType<DirectoryServicesConfigurationSettings>()
                .As<IDirectoryServicesConfigurationSettings>()
                .As<IHasConfigurationSettings>()
                .As<IHasConfigurationSettingsResource>()
                .As<IContributeMappings>()
                .InstancePerDependency();

            builder.RegisterType<DirectoryServicesUserCreationFromPrincipal>().As<ISupportsAutoUserCreationFromPrincipal>().InstancePerDependency();

            builder.RegisterType<DirectoryServicesContextProvider>().As<IDirectoryServicesContextProvider>().InstancePerDependency();
            builder.RegisterType<DirectoryServicesObjectNameNormalizer>().As<IDirectoryServicesObjectNameNormalizer>().InstancePerDependency();
            builder.RegisterType<DirectoryServicesExternalSecurityGroupLocator>()
                .As<IDirectoryServicesExternalSecurityGroupLocator>()
                .As<ICanMatchExternalGroup>()
                .InstancePerDependency();

            builder.RegisterType<DirectoryServicesCredentialValidator>()
                .As<IDirectoryServicesCredentialValidator>()
                .As<IDoesBasicAuthentication>()
                .InstancePerDependency();

            builder.RegisterType<GroupRetriever>()
                .As<IExternalGroupRetriever>()
                .InstancePerDependency();

            builder.RegisterType<UserLookup>().As<ICanLookupExternalUsers>().As<ICanLookupActiveDirectoryUsers>().InstancePerDependency();
            builder.RegisterType<UserMatcher>().As<ICanMatchExternalUser>().InstancePerDependency();

            builder.RegisterType<DirectoryServicesHomeLinksContributor>().As<IHomeLinksContributor>().InstancePerDependency();
        }
    }
}