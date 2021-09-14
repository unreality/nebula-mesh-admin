import base64
import hashlib
import secrets
import time
from datetime import datetime, timedelta
from pprint import pprint
from urllib.parse import urlencode
from functools import wraps
import pytz
import requests
from django.conf import settings
from django.contrib import messages
from django.http import HttpResponseRedirect, HttpResponse, JsonResponse
from django.shortcuts import render
from django.urls import reverse
from jose import jwt, JWTError, JWSError, jwk
from mesh import api
from mesh.lib.nebulacert import NebulaCertificate
from mesh.models import Host, Lighthouse, BlocklistHost, OTTEnroll


def session_is_authenticated(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):

        session_expires = request.session.get("expires", 0)
        session_user = request.session.get("user")

        if not session_user:
            messages.add_message(request, messages.INFO, f"Please sign in.", extra_tags='info')
            return HttpResponseRedirect("login")

        if session_user and session_expires > time.time():
            return view_func(request, *args, **kwargs)

        messages.add_message(request, messages.INFO, f"Session expired, please login again.", extra_tags='info')

        return HttpResponseRedirect("login")

    return _wrapped_view


def logout(request):
    request.session.clear()
    messages.add_message(request, messages.INFO, f"Logged out.", extra_tags='info')
    return HttpResponseRedirect(reverse('login'))


def login(request):
    return render(request, "mesh/login.html")


@session_is_authenticated
def dashboard(request):
    f = open(settings.CA_CERT)
    cert_crt_pem = f.readlines()
    cert_crt_pem = "".join(cert_crt_pem)
    f.close()

    c = NebulaCertificate()
    c.load_cert(cert_crt_pem)

    return render(
        request,
        "mesh/dashboard.html",
        {
            "cert": c,
            "subnet": settings.MESH_SUBNET,
            "notbefore": datetime.fromtimestamp(c.NotBefore),
            "notafter": datetime.fromtimestamp(c.NotAfter),
        }
    )


@session_is_authenticated
def hosts(request):

    if request.method == "POST":
        id_to_delete = request.POST.get("id")
        if id_to_delete:
            try:
                h = Host.objects.get(pk=id_to_delete)
                messages.add_message(request, messages.SUCCESS, f'Deleted host {h.fingerprint}', extra_tags='success')
                h.delete()
            except Host.DoesNotExist:
                messages.add_message(request, messages.ERROR, 'No such host', extra_tags='danger')
        else:
            messages.add_message(request, messages.ERROR, 'No host supplied', extra_tags='danger')

    h = Host.objects.all()

    return render(
        request,
        "mesh/hosts.html",
        {"hosts": h}
    )


@session_is_authenticated
def lighthouses(request):

    if request.method == "POST":
        if request.POST.get("action") == "create":
            ip_addr = request.POST.get("lighthouse_ip")
            ip_ext = request.POST.get("lighthouse_extip")
            name = request.POST.get("lighthouse_name")

            try:
                Lighthouse.objects.get(ip=ip_addr)
                messages.add_message(request, messages.ERROR, 'A lighthouse with this IP already exists', extra_tags='danger')
            except Lighthouse.DoesNotExist:
                pass

            lighthouse = Lighthouse.objects.create(ip=ip_addr, external_ip=ip_ext, name=name)
            lighthouse.save()

            messages.add_message(request, messages.SUCCESS, f'Created lighthouse {lighthouse.name}', extra_tags='success')
        else:
            id_to_delete = request.POST.get("id")
            if id_to_delete:
                try:
                    h = Lighthouse.objects.get(pk=id_to_delete)
                    messages.add_message(request, messages.SUCCESS, f'Deleted lighthouse {h.name}', extra_tags='success')
                    h.delete()
                except Lighthouse.DoesNotExist:
                    messages.add_message(request, messages.ERROR, 'No such lighthouse', extra_tags='danger')
            else:
                messages.add_message(request, messages.ERROR, 'No lighthouse supplied', extra_tags='danger')

    lighthouse_list = Lighthouse.objects.all()

    return render(request, "mesh/lighthouses.html", {"lighthouses": lighthouse_list})


@session_is_authenticated
def enroll(request):

    if request.method == "POST":
        if request.POST.get("action") == "create":
            host_name = request.POST.get("host_name")
            host_ip = request.POST.get("host_ip")
            host_groups = request.POST.get("host_groups", "")
            host_subnets = request.POST.get("host_subnets", "")
            host_expires = int(request.POST.get("host_expires") or settings.MAX_DURATION)
            ott = secrets.token_hex(32)
            ott_expires = (datetime.utcnow() + timedelta(seconds=600)).replace(tzinfo=pytz.utc)

            OTTEnroll.objects.create(
                name=host_name,
                ip=host_ip,
                groups=host_groups,
                subnets=host_subnets,
                expires=int(time.time() + host_expires),
                ott=ott,
                ott_expires=ott_expires
            )

            messages.add_message(request, messages.SUCCESS, f'Created enroll OTP <strong>{ott}</strong>', extra_tags='success')
        else:
            id_to_delete = request.POST.get("id")
            if id_to_delete:
                try:
                    h = OTTEnroll.objects.get(pk=id_to_delete)
                    messages.add_message(request, messages.SUCCESS, f'Deleted OTP {h.name}', extra_tags='success')
                    h.delete()
                except OTTEnroll.DoesNotExist:
                    messages.add_message(request, messages.ERROR, 'No such OTP', extra_tags='danger')
            else:
                messages.add_message(request, messages.ERROR, 'No OTP supplied', extra_tags='danger')

    enrol_list = OTTEnroll.objects.all()

    return render(request, "mesh/enroll.html", {"enrol_list": enrol_list})


@session_is_authenticated
def blocklist(request):

    if request.method == "POST":
        if request.POST.get("action") == "create":
            fingerprint = request.POST.get("fingerprint")
            name = request.POST.get("name", fingerprint)

            try:
                BlocklistHost.objects.get(fingerprint=fingerprint)
                messages.add_message(request, messages.ERROR, 'A blocked host with this fingerprint already exists', extra_tags='danger')
            except BlocklistHost.DoesNotExist:
                pass

            blocked_host = BlocklistHost.objects.create(fingerprint=fingerprint, name=name)
            blocked_host.save()

            messages.add_message(request, messages.SUCCESS, f'Blocked {fingerprint}', extra_tags='success')
        else:
            id_to_delete = request.POST.get("id")
            if id_to_delete:
                try:
                    h = BlocklistHost.objects.get(pk=id_to_delete)
                    messages.add_message(request, messages.SUCCESS, f'Deleted block {h.fingerprint}', extra_tags='success')
                    h.delete()
                except BlocklistHost.DoesNotExist:
                    messages.add_message(request, messages.ERROR, 'No such block', extra_tags='danger')
            else:
                messages.add_message(request, messages.ERROR, 'No block id supplied', extra_tags='danger')

    blocklist = BlocklistHost.objects.all()

    return render(request, "mesh/blocklist.html", {"blocklist": blocklist})


def oidc_login(request):
    oidc_config = api.get_oidc_config()

    if oidc_config:
        scheme = "https" if request.is_secure() else "http"
        callback_path = reverse("oidc_callback")
        redirect_uri = f"{scheme}://{request.META.get('HTTP_HOST')}{callback_path}"

        v = secrets.token_hex(24)
        v_sha = base64.urlsafe_b64encode(hashlib.sha256(v.encode('ascii')).digest()).decode('ascii')
        v_sha = v_sha.replace("=", "")

        request.session['v'] = v

        params = {
            'response_type': 'code',
            'client_id': settings.OIDC_CLIENT_ID,
            'redirect_uri': redirect_uri,
            'scope': 'openid',
            'code_challenge': v_sha,
            'code_challenge_method': 'S256'
        }
        url_encode_params = urlencode(params)

        url = f"{oidc_config['authorization_endpoint']}?{url_encode_params}"
        return HttpResponseRedirect(url)
    else:
        resp = HttpResponse("Could not retrieve oidc endpoint info")
        resp.status_code = 500
        return resp


def oidc_callback(request):
    oidc_config = api.get_oidc_config()

    if not oidc_config:
        resp = HttpResponse("Could not retrieve oidc endpoint info")
        resp.status_code = 500
        return resp

    oidc_jwks_request = requests.get(oidc_config['jwks_uri'])

    if oidc_jwks_request.status_code == 200:
        jwks_config = oidc_jwks_request.json()
    else:
        resp = HttpResponse("Could not retrieve oidc endpoint info")
        resp.status_code = 500
        return resp

    if 'code' in request.GET:
        scheme = "https" if request.is_secure() else "http"
        callback_path = reverse("oidc_callback")
        redirect_uri = f"{scheme}://{request.META.get('HTTP_HOST')}{callback_path}"

        params = {
            'grant_type': 'authorization_code',
            'code': request.GET['code'],
            'client_id': settings.OIDC_CLIENT_ID,
            'code_verifier': request.session.get('v'),
            'redirect_uri': redirect_uri,
        }
        r = requests.post(oidc_config['token_endpoint'], data=params)

        if r.status_code == 200:
            tokens = r.json()

            userinfo_resp = requests.get(
                oidc_config['userinfo_endpoint'],
                headers={
                    "Authorization": f"Bearer {tokens['access_token']}"
                }
            )

            userinfo = userinfo_resp.json()
            pprint(userinfo)

            unverified_header = jwt.get_unverified_header(tokens['access_token'])

            for k in jwks_config['keys']:
                if k['kid'] == unverified_header['kid']:
                    constructed_key = jwk.construct(k)
                    try:
                        verified_token = jwt.decode(
                            tokens['access_token'],
                            constructed_key,
                            k['alg'],
                            audience=settings.OIDC_JWT_AUDIENCE
                        )

                        for g in userinfo.get('groups', []):
                            if g == settings.OIDC_ADMIN_GROUP:
                                request.session['user'] = verified_token['email']
                                request.session['expires'] = int(time.time() + settings.OIDC_SESSION_DURATION)

                                return HttpResponseRedirect(reverse('dashboard'))

                        messages.add_message(request, messages.ERROR, 'User not in administrator group', extra_tags='danger')
                        return HttpResponseRedirect("login")
                    except JWTError:
                        messages.add_message(request, messages.ERROR, 'Token verification error',
                                             extra_tags='danger')
                        return HttpResponseRedirect("login")
        else:
            messages.add_message(request, messages.ERROR, 'Error retrieving token',
                                 extra_tags='danger')
            return HttpResponseRedirect("login")
    else:
        messages.add_message(request, messages.ERROR, 'Missing code',
                             extra_tags='danger')
        return HttpResponseRedirect("login")
