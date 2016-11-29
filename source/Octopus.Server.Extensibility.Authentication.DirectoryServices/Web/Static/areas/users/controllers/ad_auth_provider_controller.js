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

        var authUri = $scope.provider.Links["Authenticate"];
        if ($rootScope.redirectAfterLoginTo) {
            authUri += '?redirectTo=' + $location.absUrl().replace($location.path(), '') + $rootScope.redirectAfterLoginTo;
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

