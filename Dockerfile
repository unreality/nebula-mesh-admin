FROM python:3.7

WORKDIR /app

COPY . .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install gunicorn

EXPOSE 8000

VOLUME /persist

RUN chmod a+x docker_entrypoint.sh
CMD ["/app/docker_entrypoint.sh"]
