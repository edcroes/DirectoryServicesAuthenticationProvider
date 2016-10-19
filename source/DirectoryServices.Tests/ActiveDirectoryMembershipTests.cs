using NSubstitute;
using NUnit.Framework;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices;

namespace DirectoryServices.Tests
{
    [TestFixture]
    public class ActiveDirectoryMembershipTests
    {
        [Test]
        [TestCase("joe", "joe", null)]
        [TestCase("joe@example", "joe@example", null)]
        [TestCase("EXAMPLE\\joe", "joe", "EXAMPLE")]
        public void CredentialsAreNormalized(string rawUsername, string usedUsername, string usedDomain)
        {
            string usernamePart, domainPart;
            var log = Substitute.For<ILog>();
            var credentialNormalizer = new DirectoryServicesCredentialNormalizer(log);
            credentialNormalizer.NormalizeCredentials(rawUsername, out usernamePart, out domainPart);
            Assert.AreEqual(usedUsername, usernamePart);
            Assert.AreEqual(usedDomain, domainPart);
        }
    }
}