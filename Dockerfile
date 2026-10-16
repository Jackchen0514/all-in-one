FROM python:3.12-alpine
WORKDIR /app
COPY allinone ./allinone
ENV AIO_DB=/data/allinone.db AIO_PORT=8080
VOLUME /data
EXPOSE 8080
CMD ["python", "-m", "allinone"]
