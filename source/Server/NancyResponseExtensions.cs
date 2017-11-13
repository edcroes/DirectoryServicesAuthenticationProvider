using System.Collections.Generic;
using Nancy;
using Nancy.Cookies;

namespace Octopus.Server.Extensibility.Authentication.DirectoryServices
{
    public static class NancyResponseExtensions
    {
        public static Response WithCookies(this Response response, IEnumerable<INancyCookie> cookies)
        {
            foreach (var cookie in cookies)
            {
                response.Cookies.Add(cookie);
            }

            return response;
        }
    }
}