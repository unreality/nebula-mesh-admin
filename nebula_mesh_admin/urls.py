"""nebula_mesh_admin URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
# from django.contrib import admin
from django.urls import path
from mesh import api, views

urlpatterns = [
    #    path('admin/', admin.site.urls),
    path("sign", api.sign, name="sign"),
    path("config", api.config, name="config"),
    path("certs", api.certs, name="certs"),
    path("enroll", api.ott_enroll, name="ott_enroll"),

    path("login", views.login, name="login"),
    path("logout", views.logout, name="logout"),
    path("oidc_login", views.oidc_login, name="oidc_login"),
    path("oidc_callback", views.oidc_callback, name="oidc_callback"),

    path("hosts", views.hosts, name="hosts"),
    path("lighthouses", views.lighthouses, name="lighthouses"),
    path("blocklist", views.blocklist, name="blocklist"),
    path("enrollhost", views.enroll, name="enroll"),

    path("", views.dashboard, name="dashboard"),

]
