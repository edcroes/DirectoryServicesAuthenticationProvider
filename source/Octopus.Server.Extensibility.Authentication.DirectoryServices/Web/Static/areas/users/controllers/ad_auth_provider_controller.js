var module = angular.module('octopusApp.users.directoryServices');

module.controller('DirectoryServicesAuthController', function ($scope, $rootScope, octopusClient, busy, $window, $location) {

    var isSubmitting = $scope.isSubmitting = busy.create();

    $scope.name = $scope.provider.Name;

    $scope.linkHtml = $scope.provider.LinkHtml;

    var redirectToLink = function (externalProviderLink) {
        $window.location.href = externalProviderLink.ExternalAuthenticationUrl;
    };

    $scope.signIn = function() {
        if (isSubmitting.busy) {
            return;
        }

        var authUri = $scope.provider.Links["Authenticate"];
        if ($rootScope.absoluteRedirectAfterLoginTo) {
            authUri += '?redirectTo=' + $rootScope.absoluteRedirectAfterLoginTo;
        }
        else {
            authUri += '?redirectTo=/';
        }
        $window.location.href = authUri;
    };

    if ($scope.shouldAutoLogin) {
        console.log('doing auto login...');
        $scope.signIn();
    }
});

