using System;
using NSubstitute;
using NUnit.Framework;
using Octopus.Data.Model.User;
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
            var user = Substitute.For<IUser>();
            user.SecurityGroupsLastUpdated.Returns((DateTimeOffset?)null);

            Assert.IsTrue(subject.ShouldFetchExternalGroups(user));
        }

        [Test]
        public void ShouldFetchExternalGroupsIfFetchedGreaterThan7DaysAgo()
        {
            var user = Substitute.For<IUser>();
            user.SecurityGroupsLastUpdated.Returns(DateTimeOffset.UtcNow.AddDays(-8));
            user.HasSecurityGroupIds.Returns(true);

            Assert.IsTrue(subject.ShouldFetchExternalGroups(user));
        }

        [Test]
        public void ShouldFetchExternalGroupsIfGroupsIsEmpty()
        {
            var user = Substitute.For<IUser>();
            user.SecurityGroupsLastUpdated.Returns(DateTimeOffset.UtcNow.AddMinutes(-30));
            user.HasSecurityGroupIds.Returns(false);

            Assert.IsTrue(subject.ShouldFetchExternalGroups(user));
        }

        [Test]
        public void ShouldNotFetchExternalGroupsIfRecentlyFetched()
        {
            var user = Substitute.For<IUser>();
            user.SecurityGroupsLastUpdated.Returns(DateTimeOffset.UtcNow.AddMinutes(-10));
            user.HasSecurityGroupIds.Returns(true);

            Assert.IsFalse(subject.ShouldFetchExternalGroups(user));
        }

        [Test]
        public void ShouldRefreshExternalGroupsIfLastFetchedOverAnHourAgo()
        {
            var user = Substitute.For<IUser>();
            user.SecurityGroupsLastUpdated.Returns(DateTimeOffset.UtcNow.AddHours(-2));
            user.HasSecurityGroupIds.Returns(true);

            Assert.IsTrue(subject.ShouldFetchExternalGroupsInBackground(user));
        }

        [Test]
        public void ShoulNotRefreshExternalGroupsIfLastFetchedLessThanAnHourAgo()
        {
            var user = Substitute.For<IUser>();
            user.SecurityGroupsLastUpdated.Returns(DateTimeOffset.UtcNow.AddMinutes(-30));
            user.HasSecurityGroupIds.Returns(true);

            Assert.IsFalse(subject.ShouldFetchExternalGroupsInBackground(user));
        }
    }
}