//////////////////////////////////////////////////////////////////////
// TOOLS
//////////////////////////////////////////////////////////////////////
#tool "nuget:?package=GitVersion.CommandLine&prerelease"

using Path = System.IO.Path;
using IO = System.IO;
using Cake.Common.Tools;

//////////////////////////////////////////////////////////////////////
// ARGUMENTS
//////////////////////////////////////////////////////////////////////
var target = Argument("target", "Default");
var configuration = Argument("configuration", "Release");

///////////////////////////////////////////////////////////////////////////////
// GLOBAL VARIABLES
///////////////////////////////////////////////////////////////////////////////
var publishDir = "./publish";
var localPackagesDir = "../LocalPackages";
var artifactsDir = "./artifacts";
var assetDir = "./BuildAssets";
var bin451 = "/bin/Release/net451/";
var std20 = "/bin/Release/netstandard2.0/";

var gitVersionInfo = GitVersion(new GitVersionSettings {
    OutputType = GitVersionOutput.Json
});

var nugetVersion = gitVersionInfo.NuGetVersion;

///////////////////////////////////////////////////////////////////////////////
// SETUP / TEARDOWN
///////////////////////////////////////////////////////////////////////////////
Setup(context =>
{
    if(BuildSystem.IsRunningOnTeamCity)
        BuildSystem.TeamCity.SetBuildNumber(gitVersionInfo.NuGetVersion);

    Information("Building Octopus Authentication DirectoryServices v{0}", nugetVersion);
});

Teardown(context =>
{
    Information("Finished running tasks.");
});

//////////////////////////////////////////////////////////////////////
//  PRIVATE TASKS
//////////////////////////////////////////////////////////////////////

Task("__Default")
    .IsDependentOn("__Clean")
    .IsDependentOn("__Restore")
    .IsDependentOn("__Build")
    .IsDependentOn("__Pack")
	.IsDependentOn("__Publish")
	.IsDependentOn("__CopyToLocalPackages");

Task("__Clean")
    .Does(() =>
{
    CleanDirectory(artifactsDir);
    CleanDirectory(publishDir);
    CleanDirectories("./source/**/bin");
    CleanDirectories("./source/**/obj");
});

Task("__Restore")
    .Does(() => {
        DotNetCoreRestore("source", new DotNetCoreRestoreSettings
        {
            ArgumentCustomization = args => args.Append($"/p:Version={nugetVersion}")
        });
        
        NuGetRestore("./source/DirectoryServicesAuthenticationProvider.sln");
    });
	
Task("__Build")
    .Does(() =>
{
    DotNetCoreBuild("./source", new DotNetCoreBuildSettings
    {
        Configuration = configuration,
        ArgumentCustomization = args => args.Append($"/p:Version={nugetVersion}")
    });
});

Task("__Pack")
    .Does(() => {
        var solutionDir = "./source/";
        var odNugetPackDir = Path.Combine(publishDir, "od");
        var nuspecFile = "Octopus.Server.Extensibility.Authentication.DirectoryServices.nuspec";
		var files = new string[0];
		
        CreateDirectory(odNugetPackDir);
        CopyFileToDirectory(Path.Combine(assetDir, nuspecFile), odNugetPackDir);

		CopyFileToDirectory(solutionDir + "Server" + bin451 + "Octopus.Node.Extensibility.Authentication.DirectoryServices.dll", odNugetPackDir);
		CopyFileToDirectory(solutionDir + "Server" + bin451 + "Octopus.Server.Extensibility.Authentication.DirectoryServices.dll", odNugetPackDir);
        // files = new [] {
            // solutionDir + "Server" + bin451 + "Octopus.Node.Extensibility.Authentication.DirectoryServices.dll",
            // solutionDir + "Server" + bin451 + "Octopus.Server.Extensibility.Authentication.DirectoryServices.dll"
        // };
        // Zip("./", Path.Combine(odNugetPackDir, "DirectoryServices.zip"), files);
        
        NuGetPack(Path.Combine(odNugetPackDir, nuspecFile), new NuGetPackSettings {
            Version = nugetVersion,
            OutputDirectory = artifactsDir
        });
        
        var dcmNugetPackDir = Path.Combine(publishDir, "dcm");
        var dcmNuspecFile = "Octopus.DataCenterManager.Extensibility.Authentication.DirectoryServices.nuspec";
        CreateDirectory(dcmNugetPackDir);
        CopyFileToDirectory(Path.Combine(assetDir, dcmNuspecFile), dcmNugetPackDir);

        files = new [] {
            solutionDir + "DataCenterManager" + std20 + "Octopus.Node.Extensibility.Authentication.DirectoryServices.dll",
            solutionDir + "DataCenterManager" + std20 + "Octopus.DataCenterManager.Extensibility.Authentication.DirectoryServices.dll"
        };
        Zip("./", Path.Combine(dcmNugetPackDir, "DirectoryServices.zip"), files);
        
        NuGetPack(Path.Combine(dcmNugetPackDir, dcmNuspecFile), new NuGetPackSettings {
            Version = nugetVersion,
            OutputDirectory = artifactsDir
        });
});

Task("__Publish")
    .WithCriteria(BuildSystem.IsRunningOnTeamCity)
    .Does(() =>
{
    NuGetPush($"{artifactsDir}/Octopus.Server.Extensibility.Authentication.DirectoryServices.{nugetVersion}.nupkg", new NuGetPushSettings {
        Source = "https://octopus.myget.org/F/octopus-dependencies/api/v3/index.json",
        ApiKey = EnvironmentVariable("MyGetApiKey")
    });
    NuGetPush($"{artifactsDir}/Octopus.DataCenterManager.Extensibility.Authentication.DirectoryServices.{nugetVersion}.nupkg", new NuGetPushSettings {
        Source = "https://octopus.myget.org/F/octopus-dependencies/api/v3/index.json",
        ApiKey = EnvironmentVariable("MyGetApiKey")
    });

    if (gitVersionInfo.PreReleaseLabel == "")
    {
        NuGetPush($"{artifactsDir}/Octopus.Server.Extensibility.Authentication.DirectoryServices.{nugetVersion}.nupkg", new NuGetPushSettings {
            Source = "https://www.nuget.org/api/v2/package",
            ApiKey = EnvironmentVariable("NuGetApiKey")
        });
        NuGetPush($"{artifactsDir}/Octopus.DataCenterManager.Extensibility.Authentication.DirectoryServices.{nugetVersion}.nupkg", new NuGetPushSettings {
            Source = "https://www.nuget.org/api/v2/package",
            ApiKey = EnvironmentVariable("NuGetApiKey")
        });
    }
});


Task("__CopyToLocalPackages")
    .WithCriteria(BuildSystem.IsLocalBuild)
    .IsDependentOn("__Pack")
    .Does(() =>
{
    CreateDirectory(localPackagesDir);
    CopyFileToDirectory(Path.Combine(artifactsDir, $"Octopus.Server.Extensibility.Authentication.DirectoryServices.{nugetVersion}.nupkg"), localPackagesDir);

    CopyFileToDirectory(Path.Combine(artifactsDir, $"Octopus.DataCenterManager.Extensibility.Authentication.DirectoryServices.{nugetVersion}.nupkg"), localPackagesDir);
});

//////////////////////////////////////////////////////////////////////
// TASKS
//////////////////////////////////////////////////////////////////////
Task("Default")
    .IsDependentOn("__Default");

//////////////////////////////////////////////////////////////////////
// EXECUTION
//////////////////////////////////////////////////////////////////////
RunTarget(target);
