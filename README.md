# multitenantauth
Multitenant app using subdomains for individual tenants

## Purpose
Use subdomains, e.g. https://cust1.app.com, https://cust2.app.com, etc. to land users on pages rendered for their application tenancy.
Use Azure AD multi-tenant app support to authenticate users.
Use a single registered redirect url.
ensure that once authenticated, user will always land on pages rendered for subdomain associated with their AAD tenant id.

