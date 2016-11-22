using System.Collections.Generic;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Content;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.Web
{
    public class DirectoryServicesCSSContributor : IContributesCSS
    {
        public IEnumerable<string> GetCSSUris(string requestDirectoryPath)
        {
            yield return "styles/DirectoryServices.css";
        }
    }
}