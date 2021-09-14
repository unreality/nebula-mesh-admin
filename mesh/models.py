from django.utils import timezone
from django.db import models
import pytz


class Host(models.Model):
    ip = models.CharField(max_length=100)
    fingerprint = models.CharField(max_length=64)
    name = models.CharField(max_length=128)
    expires = models.DateTimeField()

    @property
    def expired(self):
        return self.expires.astimezone(pytz.UTC) <= timezone.localtime().astimezone(pytz.UTC)


class OTTEnroll(models.Model):
    ott = models.CharField(max_length=64)
    ott_expires = models.DateTimeField()

    ip = models.CharField(max_length=32)
    groups = models.CharField(max_length=250, default="", blank=True)
    subnets = models.CharField(max_length=250, default="", blank=True)

    expires = models.IntegerField()
    is_lighthouse = models.BooleanField(default=False)

    name = models.CharField(max_length=100)


class Lighthouse(models.Model):
    ip = models.CharField(max_length=100)
    external_ip = models.CharField(max_length=100)
    name = models.CharField(max_length=255, default="")


class BlocklistHost(models.Model):
    fingerprint = models.CharField(max_length=128)
    name = models.CharField(max_length=255, default="")
