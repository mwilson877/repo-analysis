# GitHub Supply Chain Analysis Tool

This tool analyzes GitHub repositories for potential supply chain compromises using a multi-phase pipeline. **Note:** The analysis is currently optimized for Python repositories only.

## Features

- **Commit Data Collection:**  
  Retrieves commit data (including commit messages, file diffs, and author information) from a specified GitHub repository.

- **Commit Message Analysis:**  
  Uses transformer models (e.g., *facebook/bart-large-mnli*, *all-MiniLM-L6-v2*) and clustering to score commit messages for suspicious content.

- **Code Diff Analysis:**  
  Generates code embeddings with CodeBERT and applies anomaly detection (Isolation Forest), rule-based risky pattern matching, and zero-shot classification to analyze code changes.

- **Ensemble Integration:**  
  Combines commit message risk, code diff risk, and metadata (author-based risk) into a final risk score for each commit.

  **Dockerized Deployment:**  
  The tool is containerized using Docker for easy deployment on Linux and Windows (using Linux containers). The Dockerfile pre-downloads required models during the build process to avoid repeated downloads at runtime.

## Installation

### Native Setup
1. **Clone the Repository:**
   ```bash
   git clone https://github.com/mwilson877/repo-analysis
   cd repo-analysis
   ```
2. **Install Python Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
### Docker Setup
1. **Clone the Repository:**
   ```bash
   git clone https://github.com/mwilson877/repo-analysis
   cd repo-analysis
   ```
2. **Build the Docker Image:**
   ```bash
   docker build -t github-analysis-tool .
   ```

## Usage

### Running Natively
Run the main script with the required arguments:
```bash
python github_analysis.py --repo <owner/repo> [--api-key YOUR_API_KEY] [--days number] [-v] [-w] [-h]
```
- ```--repo```: **(Required)** GitHub repository in the format ```owner/repo``` (e.g., ```psf/requests```).
- ```--api-key```: **(Optional)** GitHub API key for increased rate limits.
- ```--days```: **(Optional)** Number of days to look back (default: 90).
- ```-v, --verbose```: **(Optional)** Show full output (verbose mode).
- ```-w, --write```: **(Optional)** Write JSON output files to disk.
- ```-h, --help```: **(Optional)** Show help message and exit.

**Example:**
  ```bash
  python github_analysis.py --repo psf/requests --days 120 -v
  ```
### Running via Docker
Run the main script with the required arguments:
```bash
docker run github-analysis-tool --repo psf/requests --days 120
```

## Troubleshooting

- **Performance:**
  
  Running transformer models on CPU can be slow. For better performance, consider using a GPU-enabled Docker setup. Alteranatively, consider giving your docker setup more CPU cores.
  
- **API Rate Limits:**
  
  If you run into GitHub API rate limits, use the ```--api-key``` argument with your github API key. The primary rate limit for unauthenticated requests is 60 requests per hour and 5,000 requests per hour for authenticated users. 
