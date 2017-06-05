var providerName = "Directory Services";

function directoryServicesAuthProvider(octopusClient) {
    this.octopusClient = octopusClient;

    this.name = providerName;
    this.linkHtml =
        '<a><div class="external-provider-button ds-button"><img src="' + octopusClient.resolve("~/images/directory_services_signin_buttons/microsoft-logo.svg") + '"><div>Sign in with a domain account</div></div></a>';

    this.signIn = function (authLink, redirectAfterLoginToLink, success) {
        console.log(this.name + " clicked");

        var authUri = authLink;
        if (redirectAfterLoginToLink) {
            authUri += "?redirectTo=" + redirectAfterLoginToLink;
        } else {
            authUri += "?redirectTo=" + octopusClient.resolve("~/");
        }

        window.location.href = authUri;
    };

    return {
        Name: this.name,
        LinkHtml: this.linkHtml,
        SignIn: this.signIn
    };
}

console.log("Registering " + providerName + " auth provider");
window.Octopus.registerExtension(providerName, "auth_provider", directoryServicesAuthProvider);