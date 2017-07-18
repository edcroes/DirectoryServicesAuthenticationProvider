using Autofac;
using Octopus.DataCenterManager.Extensibility.Authentication.DirectoryServices.Web;
using Octopus.Node.Extensibility.Authentication.DirectoryServices;
using Octopus.Node.Extensibility.Extensions.Infrastructure.Web.Content;

namespace Octopus.DataCenterManager.Extensibility.Authentication.DirectoryServices
{
    public class DataCenterManagerDirectoryServicesExtension : DirectoryServicesExtension
    {
        public override void Load(ContainerBuilder builder)
        {
            base.Load(builder);

            builder.RegisterType<DirectoryServicesStaticContentFolders>().As<IContributesStaticContentFolders>().InstancePerDependency();
        }
    }
}