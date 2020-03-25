using System;
using System.Collections.Concurrent;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.IntegratedAuthentication
{
    class IntegratedChallengeTracker : IIntegratedChallengeTracker
    {
        readonly ConcurrentDictionary<string, DateTimeOffset> connections = new ConcurrentDictionary<string, DateTimeOffset>();
        
        public bool IsConnectionKnown(string connectionId)
        {
            return connections.ContainsKey(connectionId);
        }

        public void SetConnectionChallengeInitiated(string connectionId)
        {
            if (IsConnectionKnown(connectionId))
                return;
            var initiated = DateTimeOffset.Now;
            connections.AddOrUpdate(connectionId, c => initiated, (c, i) => initiated);
        }

        public void SetConnectionChallengeCompleted(string connectionId)
        {
            if (!IsConnectionKnown(connectionId))
                return;
            connections.TryRemove(connectionId, out DateTimeOffset initiated);
        }
    }

    interface IIntegratedChallengeTracker
    {
        bool IsConnectionKnown(string connectionId);
        void SetConnectionChallengeInitiated(string connectionId);
        void SetConnectionChallengeCompleted(string connectionId);
    }
}