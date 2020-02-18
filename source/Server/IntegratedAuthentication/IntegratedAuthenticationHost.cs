using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.Configuration;
using Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web;
using Octopus.Server.Extensibility.HostServices.Web;
using AuthenticationSchemes = Microsoft.AspNetCore.Server.HttpSys.AuthenticationSchemes;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.IntegratedAuthentication
{
    class IntegratedAuthenticationHost : IShareWebHostLifetime
    {
        readonly ILog log;
        readonly IWebPortalConfigurationStore configuration;
        readonly IDirectoryServicesConfigurationStore configurationStore;
        readonly IIntegratedAuthenticationHandler handler;
        IWebHost host;

        public IntegratedAuthenticationHost(ILog log,
            IWebPortalConfigurationStore configuration,
            IDirectoryServicesConfigurationStore configurationStore,
            IIntegratedAuthenticationHandler handler)
        {
            this.log = log;
            this.configuration = configuration;
            this.configurationStore = configurationStore;
            this.handler = handler;
        }

        public Task StartAsync()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // HttpSys is only supported on Windows, and we're not planning to support Negotiate on Kestrel at this point
                return Task.CompletedTask;
            }

            var prefixes = GetListenPrefixes();

            var builder = new WebHostBuilder();
            
            builder.UseHttpSys(options =>
            {
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
                         context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                         return Task.CompletedTask;
                     }
            
                     return handler.HandleRequest(context);
                 });
             });
            
            host = builder.Build();
            return host.StartAsync();
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

            return prefixes.ToArray();
        }

        public async Task StopAsync()
        {
            if (host == null)
                return;

            await host.StopAsync();
            host.Dispose();
            host = null;
        }
    }
}