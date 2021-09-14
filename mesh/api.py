import ipaddress
import json
import time
from datetime import datetime, timedelta

import pytz
import requests
from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from jose import jwt, JWTError, JWSError, jwk

from mesh.lib.nebulacert import NebulaCertificate
from mesh.models import Host, Lighthouse, BlocklistHost, OTTEnroll


def get_oidc_config():
    oidc_config_request = requests.get(settings.OIDC_CONFIG_URL)

    if oidc_config_request.status_code == 200:
        oidc_config = oidc_config_request.json()

        return oidc_config
    else:
        return None


@csrf_exempt
def ott_enroll(request):

    if request.method == 'POST':
        try:
            sign_request = json.loads(request.body)
        except ValueError:
            resp = JsonResponse({'status': 'error', 'message': 'Invalid JSON payload'})
            resp.status_code = 400
            return resp

        ott_str = sign_request.get('ott')
        if not ott_str:
            resp = JsonResponse({'status': 'error', 'message': 'No OTT'})
            resp.status_code = 400
            return resp

        public_key = sign_request.get('public_key')
        if not public_key:
            resp = JsonResponse({'status': 'error', 'message': 'No public_key'})
            resp.status_code = 400
            return resp

        try:
            ott = OTTEnroll.objects.get(ott=ott_str, ott_expires__gt=datetime.utcnow().replace(tzinfo=pytz.utc))

            nc = NebulaCertificate()
            nc.Name = ott.name
            nc.Groups = ott.groups.split(",")
            nc.NotBefore = int(time.time())
            nc.NotAfter = ott.expires
            nc.set_public_key_pem(public_key)
            nc.IsCA = False

            nc.Ips = [ott.ip]
            nc.Subnets = []

            f = open(settings.CA_KEY)
            signing_key_pem = "".join(f.readlines())
            f.close()

            f = open(settings.CA_CERT)
            signing_cert_pem = "".join(f.readlines())
            f.close()

            s = nc.sign_to_pem(signing_key_pem=signing_key_pem,
                               signing_cert_pem=signing_cert_pem)

            host = Host(
                ip=ott.ip,
                fingerprint=nc.fingerprint().hexdigest(),
                name=ott.name,
                expires=datetime.fromtimestamp(ott.expires, tz=pytz.utc)
            )
            host.save()

            static_host_map = {}
            lighthouses = []
            blocklist = []

            for lighthouse in Lighthouse.objects.all():
                static_host_map[lighthouse.ip] = lighthouse.external_ip.split(",")
                lighthouses.append(lighthouse.ip)

            for b in BlocklistHost.objects.all():
                blocklist.append(b.fingerprint)

            ott.delete()

            return JsonResponse({
                'certificate': s,
                'static_host_map': static_host_map,
                'lighthouses': lighthouses,
                'blocklist': blocklist
            })

        except OTTEnroll.DoesNotExist:
            resp = JsonResponse({'status': 'error', 'message': 'Invalid enrollment token'})
            resp.status_code = 401
            return resp

    return HttpResponse("")


@csrf_exempt
def sign(request):

    if request.method == 'POST':
        try:
            sign_request = json.loads(request.body)
        except ValueError:
            resp = JsonResponse({'status': 'error', 'message': 'Invalid JSON payload'})
            resp.status_code = 400
            return resp

        auth_header = request.headers.get("Authorization")
        auth_tokens = auth_header.split(" ", 2)

        if len(auth_tokens) == 2:
            auth_jwt = auth_tokens[1]

            oidc_config = get_oidc_config()

            oidc_jwks_request = requests.get(oidc_config['jwks_uri'])

            if oidc_jwks_request.status_code == 200:
                jwks_config = oidc_jwks_request.json()
                unverified_header = jwt.get_unverified_header(auth_jwt)

                for k in jwks_config['keys']:
                    if k['kid'] == unverified_header['kid']:
                        constructed_key = jwk.construct(k)
                        try:
                            verified_token = jwt.decode(auth_jwt,
                                                        constructed_key,
                                                        k['alg'],
                                                        audience=settings.OIDC_JWT_AUDIENCE)

                            if not sign_request.get("public_key"):
                                resp = JsonResponse({'status': 'error', 'message': "invalid signing request: no public_key"})
                                resp.status_code = 401
                                return resp

                            duration = int(sign_request.get("duration", settings.DEFAULT_DURATION))
                            duration = min(duration, settings.MAX_DURATION)

                            nc = NebulaCertificate()
                            nc.Name = verified_token.get("email")
                            nc.Groups = verified_token.get("groups", [])
                            nc.NotBefore = int(time.time())
                            nc.NotAfter = int(time.time() + duration)
                            nc.set_public_key_pem(sign_request.get("public_key"))
                            nc.IsCA = False

                            subnet_iface = ipaddress.ip_interface(settings.MESH_SUBNET)
                            iface = ipaddress.ip_interface(settings.USER_SUBNET)
                            host = None
                            for ip in iface.network:
                                if ip == iface.network.network_address:
                                    continue

                                if ip == iface.network.broadcast_address:
                                    continue

                                ip_str = f"{str(ip)}/{subnet_iface.network.prefixlen}"
                                try:
                                    host = Host.objects.get(ip=ip_str)
                                    if host.expired:  # if the host is expired, re-use it
                                        host.name = verified_token.get("email")
                                        host.expires = (datetime.utcnow() + timedelta(seconds=duration)).replace(tzinfo=pytz.utc)
                                        host.save()

                                        break

                                except Host.DoesNotExist:
                                    host = Host(
                                        ip=ip_str,
                                        fingerprint=nc.fingerprint().hexdigest(),
                                        name=verified_token.get("email"),
                                        expires=(datetime.utcnow() + timedelta(seconds=duration)).replace(tzinfo=pytz.utc)
                                    )

                                    host.save()
                                    break

                            if not host:
                                resp = JsonResponse({'status': 'error', 'message': "no free ip in subnet"})
                                resp.status_code = 500
                                return resp

                            nc.Ips = [host.ip]
                            nc.Subnets = []

                            f = open(settings.CA_KEY)
                            signing_key_pem = "".join(f.readlines())
                            f.close()

                            f = open(settings.CA_CERT)
                            signing_cert_pem = "".join(f.readlines())
                            f.close()

                            s = nc.sign_to_pem(signing_key_pem=signing_key_pem,
                                               signing_cert_pem=signing_cert_pem)

                            host.fingerprint = nc.fingerprint().hexdigest()
                            host.save()

                            static_host_map = {}
                            lighthouses = []
                            blocklist = []

                            for lighthouse in Lighthouse.objects.all():
                                static_host_map[lighthouse.ip] = lighthouse.external_ip.split(",")
                                lighthouses.append(lighthouse.ip)

                            for b in BlocklistHost.objects.all():
                                blocklist.append(b.fingerprint)

                            return JsonResponse({
                                'certificate': s,
                                'static_host_map': static_host_map,
                                'lighthouses': lighthouses,
                                'blocklist': blocklist
                            })

                        except JWTError:
                            resp = JsonResponse({'status': 'error', 'message': "Token verification error"})
                            resp.status_code = 401
                            return resp

            else:
                resp = JsonResponse({'status': 'error', 'message': "Could not retrieve jwks info"})
                resp.status_code = 500
                return resp


def certs(request):
    f = open(settings.CA_CERT)
    signing_cert_pem = f.readlines()
    f.close()

    return HttpResponse(signing_cert_pem)


def config(request):
    scheme = "https" if request.is_secure() else "http"

    callback_path = reverse("sign")
    sign_endpoint = f"{scheme}://{request.META.get('HTTP_HOST')}{callback_path}"

    callback_path = reverse("certs")
    certs_endpoint = f"{scheme}://{request.META.get('HTTP_HOST')}{callback_path}"

    f = open(settings.CA_CERT)
    signing_cert_pem = f.readlines()
    f.close()

    return JsonResponse({
        "oidcConfigURL": settings.OIDC_CONFIG_URL,
        "oidcClientID": settings.OIDC_CLIENT_ID,
        "signEndpoint": sign_endpoint,
        "certEndpoint": certs_endpoint,
        "ca": "".join(signing_cert_pem),
    })
