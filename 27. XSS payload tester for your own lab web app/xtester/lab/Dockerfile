FROM python:3.12-slim

# Intentionally deliberately-vulnerable lab target — do NOT use in production.
ENV VULN_LAB_ALLOW=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /lab

COPY vuln_app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY vuln_app/ .

EXPOSE 5001

CMD ["gunicorn", "-b", "0.0.0.0:5001", "-w", "1", "app:app"]