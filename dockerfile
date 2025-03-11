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

# Pre-download and cache the Facebook Bart model
RUN python -c "from transformers import AutoModel, AutoTokenizer; \
    AutoModel.from_pretrained('facebook/bart-large-mnli'); \
    AutoTokenizer.from_pretrained('facebook/bart-large-mnli')"

# Pre-download and cache the Sentence Transformers model
RUN python -c "from sentence_transformers import SentenceTransformer; \
    SentenceTransformer('all-MiniLM-L6-v2')"

# Pre-download and cache the CodeBERT model
RUN python -c "from transformers import AutoModel, AutoTokenizer; \
    AutoModel.from_pretrained('microsoft/codebert-base'); \
    AutoTokenizer.from_pretrained('microsoft/codebert-base')"

# Copy the rest of your application code into the container
COPY . /app/

# Ensure entrypoint.sh is executable
RUN chmod +x /app/github_analysis.py

# Set the default entrypoint script
ENTRYPOINT ["/app/github_analysis.py"]
