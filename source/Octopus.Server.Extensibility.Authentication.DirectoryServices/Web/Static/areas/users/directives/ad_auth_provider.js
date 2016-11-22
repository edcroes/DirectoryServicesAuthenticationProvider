var module = angular.module('octopusApp.users.directoryServices');

module.directive("activeDirectoryAuthProvider", function () {
    return {
        restrict: 'E',
        replace: true,
        transclude: true,
        controller: 'DirectoryServicesAuthController',
        scope: {
            provider: '=',
            shouldAutoLogin: '='
        },
        template: '<a ng-click="signIn()"><div class="external-provider-button ds-button"><img src="images/directory_services_signin_buttons/microsoft-logo.svg"><div>Sign in with a domain account</div></div></a>'
    };
});
