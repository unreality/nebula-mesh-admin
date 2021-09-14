#!/bin/bash
python manage.py migrate
python manage.py collectstatic --noinput
exec gunicorn -b 0.0.0.0:8000 -t 90 -w 4 nebula_mesh_admin.wsgi
