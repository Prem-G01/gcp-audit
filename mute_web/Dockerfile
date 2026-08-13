# Builds the "Mute this alert" Cloud Run service. Build context must be the
# repo root (this app imports src/muting.py). Built via Cloud Build, not
# local Docker -- see mute_web/cloudbuild.yaml and
# scripts/deploy_mute_web.ps1 / .sh, which invoke it with
# `gcloud builds submit --config=mute_web/cloudbuild.yaml`.
FROM python:3.12-slim

WORKDIR /app

COPY mute_web/requirements.txt ./mute_web/requirements.txt
RUN pip install --no-cache-dir -r mute_web/requirements.txt

COPY src ./src
COPY mute_web ./mute_web

ENV PYTHONUNBUFFERED=1
EXPOSE 8080

CMD ["gunicorn", "--bind=0.0.0.0:8080", "--workers=2", "--threads=4", "--timeout=30", "mute_web.app:app"]
