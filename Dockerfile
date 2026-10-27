# Dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000 8080

ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

CMD ["python", "dropoutjeep.py"]
