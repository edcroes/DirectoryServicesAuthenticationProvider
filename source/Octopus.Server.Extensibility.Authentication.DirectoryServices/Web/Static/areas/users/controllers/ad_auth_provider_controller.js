var module = angular.module('octopusApp.users.directoryServices');

module.controller('DirectoryServicesAuthController', function ($scope, $rootScope, octopusClient, busy, $window, $location) {

    $scope.name = $scope.provider.Name;

    $scope.linkHtml = $scope.provider.LinkHtml;

    $scope.resolveLink = function (link) {
        if (link)
            return octopusClient.resolve(link);
        return null;
    }

    $scope.signIn = function() {
        if ($scope.isSubmitting.busy) {
            return;
        }

        var authUri = $scope.resolveLink($scope.provider.Links["Authenticate"]);
        if ($rootScope.redirectAfterExternalLoginTo) {
            authUri += '?redirectTo=' + $rootScope.redirectAfterExternalLoginTo;
        }
        else {
            authUri += '?redirectTo=' + octopusClient.resolve('~/');
        }
        $window.location.href = authUri;
    };

    if ($scope.shouldAutoLogin) {
        $scope.signIn();
    }
});

