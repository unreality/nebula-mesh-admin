Nebula Mesh Admin
-----------------

Nebula Mesh Admin is a simple controller for [Nebula](https://github.com/slackhq/nebula). It allows you to issue short-lived certificates to users using OpenID authentication to give a traditional 'sign on' flow to users, similar to traditional VPNs.

### Quick Start

```commandline
git clone https://github.com/unreality/nebula-mesh-admin.git
docker build -t nebula-mesh-admin:latest nebula-mesh-admin/
docker volume create nebula-vol
docker run -d -p 8000:8000 -e OIDC_CONFIG_URL=your_oidc_config_url -e OIDC_CLIENT_ID=your_oidc_client_id -v nebula-vol:/persist nebula-mesh-admin:latest
```

### Environment settings

Required variables:
* ``OIDC_CONFIG_URL`` - URL for the .well-known configuration endpoint. For Keycloak installs this will be in the format http://**your-keycloak-host**/auth/realms/**your-realm-name**/.well-known/openid-configuration
* ``OIDC_CLIENT_ID`` - The OIDC client ID you have created for the Mesh Admin
* ``OIDC_JWT_AUDIENCE`` (default is 'account') - The OIDC server will return a JWT with a specific ``audience`` - for Keycloak installs this is 'account', other OIDC providers may specify something different
* ``OIDC_ADMIN_GROUP`` (default is 'admin') - The OIDC server must have a 'groups' element in the ``userinfo``. If this value is in the groups list, the user can log into the admin area. For keycloak installs this means adding a Groups Mapper to your client in the Keycloak admin area (when in your client, click on the mappers tab, and add a new mapper - choosing the User Group Membership as the type)


Optional variables:
* ``OIDC_SESSION_DURATION`` (default 1 hr) - How long a user session stays active in the admin console
* ``DEFAULT_DURATION`` (default 8 hrs) - default time for a short-lived certificate
* ``MAX_DURATION`` (default 10 hrs) - maximum time for a short-lived certificate
* ``MESH_SUBNET`` (default 192.168.11.0/24) - mesh subnet
* ``USER_SUBNET`` (default 192.168.11.192/26) - ip pool for short-lived (user) certificates
* ``CA_KEY`` - path to CA key. If not specified one is generated
* ``CA_CERT`` - path to CA cert. If not specified one is generated
* ``CA_NAME`` (default 'Nebula CA') - If a CA cert/keypair is generated, this is the name specified when generating
* ``CA_EXPIRY`` (default 2 years) - If a CA cert/keypair is generated, this is expiry time used when generating
* ``TIME_ZONE`` (default UTC) - timezone for rendering expiry times
* ``SECRET_KEY_FILE`` - secret key file for holding a Django SECRET_KEY. If not specified one is generated
