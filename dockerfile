FROM python:3.9

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
 && rm -rf /var/lib/apt/lists/*

# Upgrade pip
RUN pip install --upgrade pip

# Set the working directory
WORKDIR /app

# Copy requirements.txt first for caching dependencies
COPY requirements.txt /app/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application code into the container
COPY . /app/

# Ensure entrypoint.sh is executable
RUN chmod +x /app/entrypoint.sh

# Set the default entrypoint script
ENTRYPOINT ["/app/entrypoint.sh"]

