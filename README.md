# multitenantauth
Multitenant app using subdomains for individual tenants

## Purpose

Sample [Azure AD multitenant application](https://learn.microsoft.com/en-us/azure/active-directory/develop/single-and-multi-tenant-apps) using subdomains. Users use urls like https://cust1.app.com, https://cust2.app.com, etc. to arrive at their tenant specific application areas. Application is registered in AAD with a single redirect uri. Sample's logic (all in Program.cs) will ensure that users can only navigate to urls with their tenant-specific subdomain. 

## Deployment

This sample is deployed to Azure Web App service. It is configured with three [custom domains](https://learn.microsoft.com/en-us/azure/app-service/app-service-web-tutorial-custom-domain?tabs=root%2Cazurecli):

- beitmerari.com
- cust1.beitmerari.com
- cust2.beitmerari.com

The mapping of user AAD tenant id to subdomain is specified in the application configuration file (appSettings.json).

## Azure AD registration

Application is registered as a web application with a single redirect url: https://beitmerari.com/signin-oidc


