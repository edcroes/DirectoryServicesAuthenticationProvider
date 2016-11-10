using NSubstitute;
using NUnit.Framework;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.DirectoryServices;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;

namespace DirectoryServices.Tests
{
    [TestFixture]
    public class IntegratedAuthenticationRedirectUrlTests
    {
        [Test]
        public void NonLocalRedirectUrlCausesAWarningToBeLogged()
        {
            var log = Substitute.For<ILog>();
            var module = new IntegratedAuthenticationModule(log, Substitute.For<IAuthCookieCreator>(), Substitute.For<IApiActionResponseCreator>());

            module.IsLocalUrl("http://site1", "http://anotherSite");

            log.Received(1).WarnFormat(Arg.Any<string>(), "http://site1", "http://anotherSite");
        }

        [TestCase("http://site1", "/folder1/api", ExpectedResult = true)]
        [TestCase("http://site1", "~/folder1/api", ExpectedResult = true)]
        [TestCase("http://site1", "http://site1/folder1/api", ExpectedResult = true)]
        [TestCase("http://site1", "folder1/api", ExpectedResult = false)]
        [TestCase("http://site1", "http://site2/folder1/api", ExpectedResult = false)]
        public bool IsPathLocalTest(string directoryPath, string url)
        {
            var log = Substitute.For<ILog>();
            var module = new IntegratedAuthenticationModule(log, Substitute.For<IAuthCookieCreator>(), Substitute.For<IApiActionResponseCreator>());

            return module.IsLocalUrl(directoryPath, url);
        }
    }
}