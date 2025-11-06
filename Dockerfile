# syntax=docker/dockerfile:1
FROM python:3.11-slim

# Set the working directory
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the source code into the container
COPY src ./src

# Set environment variables
ENV PYTHONPATH=/app/src

# Expose the port the app runs on
EXPOSE 5000

# Set the entry point for the application
CMD ["uvicorn", "email_security_check.api:app", "--host", "0.0.0.0", "--port", "5000"]