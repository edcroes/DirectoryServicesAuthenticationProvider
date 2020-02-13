using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.HttpSys;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Configuration;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web;
using Octopus.Server.Extensibility.HostServices.Web;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.IntegratedAuthentication
{
    class IntegratedAuthenticationHost : IExecuteWhenServerStarts
    {
        readonly ILog log;
        readonly IWebPortalConfigurationStore configuration;
        readonly IDirectoryServicesConfigurationStore configurationStore;
        readonly IntegratedAuthenticationHandler handler;

        public IntegratedAuthenticationHost(ILog log,
            IWebPortalConfigurationStore configuration,
            IDirectoryServicesConfigurationStore configurationStore,
            IntegratedAuthenticationHandler handler)
        {
            this.log = log;
            this.configuration = configuration;
            this.configurationStore = configurationStore;
            this.handler = handler;
        }

        public void OnHostStarting() {}

        public void OnHostStarted()
        {
            var prefixes = GetListenPrefixes();

            var builder = new WebHostBuilder();
            
            builder.UseHttpSys(options =>
            {
                options.AllowSynchronousIO = true;
                options.MaxRequestBodySize = null;
            
                options.Authentication.Schemes = MapAuthenticationScheme();
                options.Authentication.AllowAnonymous = false;
            
                foreach (var baseUri in prefixes)
                {
                    var prefix = baseUri.ToString();
            
                    if (!baseUri.Host.Contains("."))
                    {
                        prefix = prefix.Replace("localhost", "+");
                    }
            
                    options.UrlPrefixes.Add(prefix);
                }
            });
            
             builder.Configure(app =>
             {
                 app.Use((context, func) =>
                 {
                     if (string.IsNullOrWhiteSpace(context.User.Identity.Name))
                     {
                         context.Response.StatusCode = 401;
                         return Task.CompletedTask;
                     }
            
                     handler.HandleRequest(context);
                     return Task.CompletedTask;
                 });
             });
            
            var host = builder.Build();
            host.Start();
        }

        AuthenticationSchemes MapAuthenticationScheme()
        {
            switch (configurationStore.GetAuthenticationScheme())
            {
                case System.Net.AuthenticationSchemes.Ntlm:
                    return AuthenticationSchemes.NTLM;
                case System.Net.AuthenticationSchemes.Negotiate:
                    return AuthenticationSchemes.Negotiate;
                case System.Net.AuthenticationSchemes.IntegratedWindowsAuthentication:
                    return AuthenticationSchemes.Kerberos;
            }
            return AuthenticationSchemes.None;
        }

        Uri[] GetListenPrefixes()
        {
            var setting = configuration.GetCurrentNodeWebPortalConfiguration().ListenPrefixes;

            var prefixes = new List<Uri>();

            if (setting.Any())
            {
                var values = setting.Select(v => v.Trim()).Where(v => v.Length > 0).ToArray();

                foreach (var value in values)
                {
                    log.Trace("Adding listen prefix: " + value);

                    try
                    {
                        prefixes.Add(new Uri(value.TrimEnd('/') + DirectoryServicesConstants.IntegratedAuthVirtualDirectory, UriKind.Absolute));
                    }
                    catch (Exception ex)
                    {
                        log.Error(ex);
                        throw new UriFormatException("Unable to parse listen prefix '" + value + "': " + ex.Message, ex);
                    }
                }
            }

            if (prefixes.Count == 0)
            {
                log.Trace("No HTTP listen prefixes were provided; defaulting to http://localhost:8050" + DirectoryServicesConstants.IntegratedAuthVirtualDirectory);
                prefixes.Add(new Uri("http://localhost:8050" + DirectoryServicesConstants.IntegratedAuthVirtualDirectory, UriKind.Absolute));
            }

            return prefixes.ToArray();
        }
    }
}