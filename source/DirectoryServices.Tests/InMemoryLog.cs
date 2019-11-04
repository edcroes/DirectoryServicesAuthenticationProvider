using System;
using System.Collections.Generic;
using Octopus.Diagnostics;

namespace DirectoryServices.Tests
{
    public class InMemoryLog : ILog
    {
        public List<(LogCategory category, Exception exception, string message)> Logs { get; }= new List<(LogCategory category, Exception exception, string message)>();
        
        public void Trace(string messageText) => Write(LogCategory.Trace, messageText);
        public void Trace(Exception error) => Write(LogCategory.Trace, error);
        public void Trace(Exception error, string messageText) => Write(LogCategory.Trace, error, messageText);
        public void TraceFormat(string messageFormat, params object[] args) => WriteFormat(LogCategory.Trace, messageFormat, args);
        public void TraceFormat(Exception error, string format, params object[] args) => WriteFormat(LogCategory.Trace, error, format, args);
        
        public void Verbose(string messageText) => Write(LogCategory.Verbose, messageText);
        public void Verbose(Exception error) => Write(LogCategory.Verbose, error);
        public void Verbose(Exception error, string messageText) => Write(LogCategory.Verbose, error, messageText);
        public void VerboseFormat(string messageFormat, params object[] args) => WriteFormat(LogCategory.Verbose, messageFormat, args);
        public void VerboseFormat(Exception error, string format, params object[] args) => WriteFormat(LogCategory.Verbose, error, format, args);

        public void Info(string messageText) => Write(LogCategory.Info, messageText);
        public void Info(Exception error) => Write(LogCategory.Info, error);
        public void Info(Exception error, string messageText) => Write(LogCategory.Info, error, messageText);
        public void InfoFormat(string messageFormat, params object[] args) => WriteFormat(LogCategory.Info, messageFormat, args);
        public void InfoFormat(Exception error, string format, params object[] args) => WriteFormat(LogCategory.Info, error, format, args);

        public void Warn(string messageText) => Write(LogCategory.Warning, messageText);
        public void Warn(Exception error) => Write(LogCategory.Warning, error);
        public void Warn(Exception error, string messageText) => Write(LogCategory.Warning, error, messageText);
        public void WarnFormat(string messageFormat, params object[] args) => WriteFormat(LogCategory.Warning, messageFormat, args);
        public void WarnFormat(Exception error, string format, params object[] args) => WriteFormat(LogCategory.Warning, error, format, args);

        public void Error(string messageText) => Write(LogCategory.Error, messageText);
        public void Error(Exception error) => Write(LogCategory.Error, error);
        public void Error(Exception error, string messageText) => Write(LogCategory.Error, error, messageText);
        public void ErrorFormat(string messageFormat, params object[] args) => WriteFormat(LogCategory.Error, messageFormat, args);
        public void ErrorFormat(Exception error, string format, params object[] args) => WriteFormat(LogCategory.Error, error, format, args);

        public void Fatal(string messageText) => Write(LogCategory.Fatal, messageText);
        public void Fatal(Exception error) => Write(LogCategory.Fatal, error);
        public void Fatal(Exception error, string messageText) => Write(LogCategory.Fatal, error, messageText);
        public void FatalFormat(string messageFormat, params object[] args) => WriteFormat(LogCategory.Fatal, messageFormat, args);
        public void FatalFormat(Exception error, string format, params object[] args) => WriteFormat(LogCategory.Fatal, error, format, args);

        public void Write(LogCategory category, string messageText) => Write(category, null, messageText);
        public void Write(LogCategory category, Exception error) => Write(category, error, null);
        public void WriteFormat(LogCategory category, string messageFormat, params object[] args) => Write(category, null, string.Format(messageFormat, args));
        public void WriteFormat(LogCategory category, Exception error, string messageFormat, params object[] args) => Write(category, error, string.Format(messageFormat, args));

        public void Write(LogCategory category, Exception error, string messageText)
        {
            lock (Logs)
                Logs.Add((category, error, messageText));
        }

        public void Flush()
        {
        }
    }
}