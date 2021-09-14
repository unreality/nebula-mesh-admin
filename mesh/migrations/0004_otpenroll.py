# Generated by Django 3.2.7 on 2021-09-11 03:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mesh', '0003_alter_host_expires'),
    ]

    operations = [
        migrations.CreateModel(
            name='OTPEnroll',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('otp', models.CharField(max_length=64)),
                ('otp_expires', models.DateTimeField()),
                ('ip', models.CharField(max_length=32)),
                ('groups', models.CharField(blank=True, default='', max_length=250)),
                ('subnets', models.CharField(blank=True, default='', max_length=250)),
                ('expires', models.IntegerField()),
                ('is_lighthouse', models.BooleanField(default=False)),
                ('name', models.CharField(max_length=100)),
            ],
        ),
    ]
