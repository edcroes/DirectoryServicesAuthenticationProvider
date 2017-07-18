using System;
using NSubstitute;
using NUnit.Framework;
using Octopus.Data.Model.User;
using Octopus.Node.Extensibility.Authentication.DirectoryServices;
using Octopus.Node.Extensibility.Authentication.DirectoryServices.DirectoryServices;
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
            var user = Substitute.For<IUser>();
            user.GetSecurityGroups(DirectoryServicesAuthentication.ProviderName).Returns(new SecurityGroups());

            Assert.IsTrue(subject.ShouldFetchExternalGroups(user));
        }

        [Test]
        public void ShouldFetchExternalGroupsIfFetchedGreaterThan7DaysAgo()
        {
            var user = Substitute.For<IUser>();
            user.GetSecurityGroups(DirectoryServicesAuthentication.ProviderName).Returns(new SecurityGroups{ GroupIds = new []{"abc"}, LastUpdated = DateTimeOffset.UtcNow.AddDays(-8) });

            Assert.IsTrue(subject.ShouldFetchExternalGroups(user));
        }

        [Test]
        public void ShouldFetchExternalGroupsIfGroupsIsEmpty()
        {
            var user = Substitute.For<IUser>();
            user.GetSecurityGroups(DirectoryServicesAuthentication.ProviderName).Returns(new SecurityGroups { GroupIds = new string[0], LastUpdated = DateTimeOffset.UtcNow.AddMinutes(-30) });

            Assert.IsTrue(subject.ShouldFetchExternalGroups(user));
        }

        [Test]
        public void ShouldNotFetchExternalGroupsIfRecentlyFetched()
        {
            var user = Substitute.For<IUser>();
            user.GetSecurityGroups(DirectoryServicesAuthentication.ProviderName).Returns(new SecurityGroups { GroupIds = new[] { "abc" }, LastUpdated = DateTimeOffset.UtcNow.AddMinutes(-10) });

            Assert.IsFalse(subject.ShouldFetchExternalGroups(user));
        }

        [Test]
        public void ShouldRefreshExternalGroupsIfLastFetchedOverAnHourAgo()
        {
            var user = Substitute.For<IUser>();
            user.GetSecurityGroups(DirectoryServicesAuthentication.ProviderName).Returns(new SecurityGroups { GroupIds = new[] { "abc" }, LastUpdated = DateTimeOffset.UtcNow.AddHours(-2) });

            Assert.IsTrue(subject.ShouldFetchExternalGroupsInBackground(user));
        }

        [Test]
        public void ShoulNotRefreshExternalGroupsIfLastFetchedLessThanAnHourAgo()
        {
            var user = Substitute.For<IUser>();
            user.GetSecurityGroups(DirectoryServicesAuthentication.ProviderName).Returns(new SecurityGroups { GroupIds = new[] { "abc" }, LastUpdated = DateTimeOffset.UtcNow.AddMinutes(-30) });

            Assert.IsFalse(subject.ShouldFetchExternalGroupsInBackground(user));
        }
    }
}