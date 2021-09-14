"""
Django settings for nebula_mesh_admin project.

Generated by 'django-admin startproject' using Django 3.2.7.

For more information on this file, see
https://docs.djangoproject.com/en/3.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.2/ref/settings/
"""
import os
import secrets
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

DEBUG = True

ALLOWED_HOSTS = ["*"]


# Application definition

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    "mesh"
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'nebula_mesh_admin.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates'
        ,
        'DIRS': [BASE_DIR / 'templates']
        ,
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'nebula_mesh_admin.wsgi.application'


# Database
# https://docs.djangoproject.com/en/3.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.environ.get("DB_FILE", "/persist/db.sqlite3"),
    }
}


# Password validation
# https://docs.djangoproject.com/en/3.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/3.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.2/howto/static-files/

STATIC_URL = '/static/'

# Default primary key field type
# https://docs.djangoproject.com/en/3.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

OIDC_CONFIG_URL = os.environ.get("OIDC_CONFIG_URL")
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID")
OIDC_ADMIN_GROUP = os.environ.get("OIDC_ADMIN_GROUP", "admin")
OIDC_JWT_AUDIENCE = os.environ.get("OIDC_JWT_AUDIENCE", "account")
OIDC_SESSION_DURATION = int(os.environ.get("OIDC_SESSION_DURATION", "3600"))

DEFAULT_DURATION = int(os.environ.get("OIDC_SESSION_DURATION", 3600*8))
MAX_DURATION = int(os.environ.get("OIDC_SESSION_DURATION", 3600*10))

MESH_SUBNET = os.environ.get("MESH_SUBNET", "192.168.11.0/24")
USER_SUBNET = os.environ.get("USER_SUBNET", "192.168.11.192/26")
CA_KEY = os.environ.get("CA_KEY", "/persist/ca.key")
CA_CERT = os.environ.get("CA_CERT", "/persist/ca.crt")

if not os.path.exists(CA_CERT):
    CA_NAME = os.environ.get("CA_NAME", "Nebula CA")
    CA_EXPIRY = int(os.environ.get("CA_EXPIRY", 60 * 60 * 24 * 365 * 2))
    print("Generating CA Key and Certificate:")
    print(f"   Name: {CA_NAME}")
    print(f"   Expiry: {CA_EXPIRY} seconds")

    from mesh.lib.nebulacert import NebulaCertificate
    import time

    nc = NebulaCertificate()
    nc.Name = "Nebula CA"
    nc.NotAfter = int(time.time() + CA_EXPIRY)  # 2 year expiry
    nc.NotBefore = int(time.time())
    cert_pem, public_key_pem, private_key_pem = nc.generate_ca()

    f = open(CA_KEY, "w")
    f.write(private_key_pem)
    f.close()

    f = open(CA_CERT, "w")
    f.write(cert_pem)
    f.close()

SECRET_KEY_FILE = os.environ.get("SECRET_KEY_FILE", "/persist/secret_key")
if not os.path.exists(SECRET_KEY_FILE):
    f = open(SECRET_KEY_FILE, "w")
    f.write(secrets.token_hex(32))
    f.flush()
    f.close()

f = open(SECRET_KEY_FILE)
SECRET_KEY = f.readline().strip()
f.close()

TIME_ZONE = os.environ.get("TIME_ZONE", "UTC")
