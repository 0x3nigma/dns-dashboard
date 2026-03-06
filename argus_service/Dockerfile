FROM python:3.12-alpine
RUN addgroup app && adduser -S -G app app
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt --no-cache-dir
COPY . .
RUN chown -R app:app /app
USER app
EXPOSE 5000
CMD ["python", "app.py"]

