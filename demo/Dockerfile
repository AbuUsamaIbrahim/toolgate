FROM python:3.12-slim
WORKDIR /app
COPY hostile-server.py .
RUN useradd --system --uid 10002 hostile
USER hostile
EXPOSE 9001
ENTRYPOINT ["python", "-u", "hostile-server.py"]
