# Use a lightweight Python base image
FROM python:3.9-slim

# Create a working directory
WORKDIR /app

# Copy only requirements first for better build caching
COPY requirements.txt /app/

# Install dependencies + gunicorn for production WSGI
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Copy the entire project into the container
COPY . /app/

# Environment variable for Flask (optional if you reference create_app directly)
ENV FLASK_APP=run.py
ENV FLASK_ENV=production

# Expose port 5000 for internal communication
EXPOSE 5000

# Use gunicorn to run your Flask app in a production-friendly manner
# "odprojekt:create_app()" dynamically references the create_app function in odprojekt/__init__.py
CMD ["gunicorn", "-b", "0.0.0.0:5000", "odprojekt:create_app()"]
