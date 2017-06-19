using System;
using NSubstitute;
using NUnit.Framework;
using Octopus.Data.Model.User;
using Octopus.Server.Extensibility.Authentication.DirectoryServices;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices;
using Octopus.Time;

namespace DirectoryServices.Tests
{
    [TestFixture]
    public class UserActiveDirectorySecurityGroupExpiryCheckerFixture
    {
        IClock clock;
        DirectoryServicesUserSecurityGroupExpiryChecker subject;

        [SetUp]
        public void SetUp()
        {
            var now = DateTimeOffset.UtcNow;

            clock = Substitute.For<IClock>();
            clock.GetUtcTime().Returns(now);

            subject = new DirectoryServicesUserSecurityGroupExpiryChecker(clock);
        }

        [Test]
        public void ShouldFetchExternalGroupsIfNotFetched()
        {
            var identity = new ActiveDirectoryIdentity("1", DirectoryServicesAuthenticationProvider.ProviderName, "test@octopus.com", "test@octopus.com", "test");

            Assert.IsTrue(subject.ShouldFetchExternalGroups(identity));
        }

        [Test]
        public void ShouldFetchExternalGroupsIfFetchedGreaterThan7DaysAgo()
        {
            var identity = new ActiveDirectoryIdentity("1", DirectoryServicesAuthenticationProvider.ProviderName, "test@octopus.com", "test@octopus.com", "test");
            identity.SetSecurityGroupIds(new [] { "abc"}, DateTimeOffset.UtcNow.AddDays(-8));

            Assert.IsTrue(subject.ShouldFetchExternalGroups(identity));
        }

        [Test]
        public void ShouldFetchExternalGroupsIfGroupsIsEmpty()
        {
            var identity = new ActiveDirectoryIdentity("1", DirectoryServicesAuthenticationProvider.ProviderName, "test@octopus.com", "test@octopus.com", "test");
            identity.SetSecurityGroupIds(new string[0], DateTimeOffset.UtcNow.AddMinutes(-30));

            Assert.IsTrue(subject.ShouldFetchExternalGroups(identity));
        }

        [Test]
        public void ShouldNotFetchExternalGroupsIfRecentlyFetched()
        {
            var identity = new ActiveDirectoryIdentity("1", DirectoryServicesAuthenticationProvider.ProviderName, "test@octopus.com", "test@octopus.com", "test");
            identity.SetSecurityGroupIds(new[] { "abc" }, DateTimeOffset.UtcNow.AddMinutes(-10));

            Assert.IsFalse(subject.ShouldFetchExternalGroups(identity));
        }

        [Test]
        public void ShouldRefreshExternalGroupsIfLastFetchedOverAnHourAgo()
        {
            var identity = new ActiveDirectoryIdentity("1", DirectoryServicesAuthenticationProvider.ProviderName, "test@octopus.com", "test@octopus.com", "test");
            identity.SetSecurityGroupIds(new[] { "abc" }, DateTimeOffset.UtcNow.AddHours(-2));

            Assert.IsTrue(subject.ShouldFetchExternalGroupsInBackground(identity));
        }

        [Test]
        public void ShoulNotRefreshExternalGroupsIfLastFetchedLessThanAnHourAgo()
        {
            var identity = new ActiveDirectoryIdentity("1", DirectoryServicesAuthenticationProvider.ProviderName, "test@octopus.com", "test@octopus.com", "test");
            identity.SetSecurityGroupIds(new[] { "abc" }, DateTimeOffset.UtcNow.AddMinutes(-30));

            Assert.IsFalse(subject.ShouldFetchExternalGroupsInBackground(identity));
        }
    }
}