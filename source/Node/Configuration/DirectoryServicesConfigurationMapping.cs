using System;
using Octopus.Node.Extensibility.Extensions.Infrastructure.Configuration;

namespace Octopus.Node.Extensibility.Authentication.DirectoryServices.Configuration
{
    public class DirectoryServicesConfigurationMapping : IConfigurationDocumentMapper
    {
        public Type GetTypeToMap() => typeof(DirectoryServicesConfiguration);
    }
}