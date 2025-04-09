FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create necessary directories
RUN mkdir -p /app/logs /app/data/downloads /app/data/keys

# Expose ports
# SSH transport
EXPOSE 2222
# HTTP transport
EXPOSE 8080

# Run the application
CMD ["python", "-m", "src.main"]