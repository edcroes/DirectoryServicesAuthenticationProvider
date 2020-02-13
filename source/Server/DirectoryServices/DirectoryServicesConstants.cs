namespace Octopus.Server.Extensibility.Authentication.DirectoryServices.DirectoryServices
{
    internal class DirectoryServicesConstants
    {
        public static string IntegratedAuthVirtualDirectory = "/ad-auth";

        public static string ChallengePath = IntegratedAuthVirtualDirectory + "/integrated-challenge";
    }
}