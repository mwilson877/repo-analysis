#!/usr/bin/env python3
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # Suppress TensorFlow warnings

import argparse
import json
import pandas as pd
import numpy as np
import re
import torch
from datetime import datetime, timedelta
from github import Github
from sentence_transformers import SentenceTransformer
from sklearn.cluster import DBSCAN
from sklearn.ensemble import IsolationForest
from transformers import pipeline, AutoModel, AutoTokenizer

#############################################
# Phase 1: Supply Chain Data Collection
#############################################
def get_commit_data(package_name, days=90, output_file=None, api_key=None):
    today_date = datetime.today()
    past_date = today_date - timedelta(days=days)
    g = Github(api_key) if api_key else Github()
    repo = g.get_repo(package_name)
    
    commits_data = []
    for commit in repo.get_commits(since=past_date):
        commit_info = {
            "commit_sha": commit.sha,
            "commit_message": commit.commit.message,
            "author": commit.author.login if commit.author is not None else "unknown_author",
            "files": []
        }
        for file in commit.files:
            commit_info["files"].append({
                "file_name": file.filename,
                "patch": file.patch
            })
        commits_data.append(commit_info)
    
    if output_file is not None:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(commits_data, f, indent=4)
        print(f"Phase 1: Commit data saved to {output_file}")
    else:
        print("Phase 1: Commit data collected (not written to file)")
    return commits_data

#############################################
# Phase 2: Commit Message Analysis (In-Memory)
#############################################
def analyze_commit_messages_from_data(commits_data, output_file=None):
    commit_texts = []
    commit_shas = []
    for commit in commits_data:
        text = commit["commit_message"]
        for file in commit["files"]:
            text += " " + file["patch"]
        commit_texts.append(text)
        commit_shas.append(commit["commit_sha"])
    
    device = "cuda" if torch.cuda.is_available() else "cpu"
    model = SentenceTransformer("all-MiniLM-L6-v2", device=device)
    embeddings = model.encode(commit_texts, convert_to_numpy=True)
    
    clustering = DBSCAN(eps=1.5, min_samples=2, metric="cosine").fit(embeddings)
    labels = clustering.labels_
    
    classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli", device=0 if device=="cuda" else -1)
    candidate_labels = ["suspicious", "malicious", "benign", "normal"]
    risk_threshold = 0.5
    analysis_results = []
    
    for sha, text, label in zip(commit_shas, commit_texts, labels):
        classification = classifier(text, candidate_labels, multi_label=True, hypothesis_template="This commit is {}.")
        suspicious_score = classification["scores"][classification["labels"].index("suspicious")]
        malicious_score = classification["scores"][classification["labels"].index("malicious")]
        risk_score = max(suspicious_score, malicious_score)
        classification_label = "Suspicious" if risk_score >= risk_threshold else "Normal"
        analysis_results.append({
            "commit_sha": sha,
            "risk_score": risk_score,
            "classification": classification_label,
            "cluster_label": "Anomalous" if label == -1 else "Normal",
            "author": next((c["author"] for c in commits_data if c["commit_sha"]==sha), "unknown_author")
        })
    
    if output_file is not None:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(analysis_results, f, indent=4)
        print(f"Phase 2: Commit message analysis complete. Results saved to {output_file}")
    else:
        print("Phase 2: Commit message analysis complete (not written to file)")
    return analysis_results

#############################################
# Phase 3: Code Diff Analysis (In-Memory)
#############################################
def analyze_code_diffs_from_data(commits_data, output_file=None):
    commit_shas = []
    code_diffs = []
    for commit in commits_data:
        sha = commit["commit_sha"]
        patches = [file_info.get("patch", "") for file_info in commit["files"]]
        combined_diff = "\n".join(patches)
        commit_shas.append(sha)
        code_diffs.append(combined_diff)
    
    print(f"Phase 3: Loaded {len(code_diffs)} code diffs from commit data.")
    
    model_name = "microsoft/codebert-base"
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModel.from_pretrained(model_name)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    model.to(device)
    model.eval()
    
    def get_codebert_embedding(code_text):
        inputs = tokenizer(code_text, return_tensors="pt", max_length=512, truncation=True)
        inputs = {k: v.to(device) for k, v in inputs.items()}
        with torch.no_grad():
            outputs = model(**inputs)
            cls_embedding = outputs.last_hidden_state[:, 0, :]
        return cls_embedding.squeeze().cpu().numpy()
    
    embeddings = np.array([get_codebert_embedding(diff) for diff in code_diffs])
    print(f"Phase 3: Generated embeddings of shape: {embeddings.shape}")
    
    iso_forest = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    iso_forest.fit(embeddings)
    predictions = iso_forest.predict(embeddings)
    anomaly_scores = iso_forest.decision_function(embeddings)
    
    RISKY_PATTERNS = [
        r"requests\.post\(", r"requests\.get\(",
        r"subprocess\.Popen\(", r"os\.system\(",
        r"eval\(", r"exec\(",
        r"base64\.b64decode\(", r"pickle\.loads\(",
        r"open\(", r"\.write\(",
        r"password\s*=", r"token\s*=", r"API_KEY\s*="
    ]
    def detect_risky_code(diff_text):
        return any(re.search(pattern, diff_text) for pattern in RISKY_PATTERNS)
    
    classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")
    def classify_code_diff(diff_text):
        labels = ["safe", "suspicious", "malicious"]
        result = classifier(diff_text, labels)
        return result["labels"][0], result["scores"][0]
    
    analysis_results = []
    for i, sha in enumerate(commit_shas):
        diff_text = code_diffs[i]
        rule_based_risk = 0.5 if detect_risky_code(diff_text) else 0.0
        classification, ai_confidence = classify_code_diff(diff_text)
        ai_risk_score = ai_confidence if classification in ["suspicious", "malicious"] else 0.0
        final_score = min(1.0, max(0.0, anomaly_scores[i] + rule_based_risk + ai_risk_score))
        analysis_results.append({
            "commit_sha": sha,
            "code_diff_anomaly_label": classification,
            "code_diff_anomaly_score": float(final_score)
        })
    
    if output_file is not None:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(analysis_results, f, indent=4)
        print(f"Phase 3: Code diff analysis complete. Results saved to {output_file}")
    else:
        print("Phase 3: Code diff analysis complete (not written to file)")
    return analysis_results

#############################################
# Phase 4: Final Ensemble Integration (In-Memory)
#############################################
def ensemble_analysis_from_data(message_data, code_diff_data, output_file=None):
    df_msg = pd.DataFrame(message_data)  # Contains commit_sha, risk_score, classification, cluster_label, author
    df_code = pd.DataFrame(code_diff_data)  # Contains commit_sha, code_diff_anomaly_label, code_diff_anomaly_score
    
    df_merged = pd.merge(df_msg, df_code, on="commit_sha", how="inner")
    print(f"Phase 4: Merged Data: {len(df_merged)} records after merging message and code diff analysis.")
    
    # Compute metadata signals using the author field
    author_commit_counts = {"trusted_dev": 500, "newbie_dev": 2, "unknown_author": 10}
    def compute_metadata_risk(author):
        count = author_commit_counts.get(author, 0)
        if count < 5:
            return 0.8
        elif count > 100:
            return 0.2
        else:
            return 0.5
    df_merged["author"] = df_merged.get("author", "unknown_author")
    df_merged["metadata_risk"] = df_merged["author"].apply(compute_metadata_risk)
    
    # Combine signals: commit message risk, code diff risk, and metadata risk
    alpha = 0.3  # Weight for commit message risk
    beta  = 0.3  # Weight for code diff risk
    gamma = 0.1  # Weight for metadata risk
    def compute_final_score(row):
        msg_score = row.get("risk_score", 0.0)
        code_score = row.get("code_diff_anomaly_score", 0.0)
        meta_score = row.get("metadata_risk", 0.0)
        return alpha * msg_score + beta * code_score + gamma * meta_score
    df_merged["final_score"] = df_merged.apply(compute_final_score, axis=1)
    
    threshold = 0.6
    def classify_final(row):
        return "High Risk" if row["final_score"] > threshold else "Normal"
    df_merged["final_classification"] = df_merged.apply(classify_final, axis=1)
    
    alerts = []
    for _, row in df_merged.iterrows():
        if row["final_classification"] == "High Risk":
            alerts.append({
                "commit_sha": row["commit_sha"],
                "final_score": row["final_score"],
                "author": row.get("author", "unknown"),
                "message_risk_score": row["risk_score"],
                "code_diff_score": row["code_diff_anomaly_score"],
                "metadata_risk": row["metadata_risk"],
                "classification_phase3": row.get("classification", ""),
                "code_diff_anomaly_label": row.get("code_diff_anomaly_label", "")
            })
    
    if alerts:
        print("High Risk Commits Detected:")
        for alert in alerts:
            print(f"Commit {alert['commit_sha']} => Score {alert['final_score']:.2f} (Author: {alert['author']})")
    else:
        print("No high risk commits detected.")
    
    if output_file is not None:
        df_merged.to_json(output_file, orient="records", indent=4)
        print(f"Phase 4: Ensemble integration complete. Results saved to {output_file}")
    else:
        print("Phase 4: Ensemble integration complete (not written to file)")
    return df_merged

#############################################
# Phase 4 (Alternate): Final Ensemble Integration (From Files)
#############################################
def ensemble_analysis(phase3_file="commit_analysis.json", phase4_file="code_diff_analysis.json", output_file=None):
    with open(phase3_file, "r", encoding="utf-8") as f:
        message_data = json.load(f)
    df_msg = pd.DataFrame(message_data)  # Contains commit_sha, risk_score, classification, cluster_label, author
    
    with open(phase4_file, "r", encoding="utf-8") as f:
        code_diff_data = json.load(f)
    df_code = pd.DataFrame(code_diff_data)  # Contains commit_sha, code_diff_anomaly_label, code_diff_anomaly_score
    
    df_merged = pd.merge(df_msg, df_code, on="commit_sha", how="inner")
    print(f"Phase 4: Merged Data: {len(df_merged)} records after merging Phase 2 and Phase 3.")
    
    author_commit_counts = {"trusted_dev": 500, "newbie_dev": 2, "unknown_author": 10}
    def compute_metadata_risk(author):
        count = author_commit_counts.get(author, 0)
        if count < 5:
            return 0.8
        elif count > 100:
            return 0.2
        else:
            return 0.5
    df_merged["author"] = df_merged.get("author", "unknown_author")
    df_merged["metadata_risk"] = df_merged["author"].apply(compute_metadata_risk)
    
    alpha = 0.3  # Weight for commit message risk
    beta  = 0.3  # Weight for code diff risk
    gamma = 0.1  # Weight for metadata risk
    def compute_final_score(row):
        msg_score = row.get("risk_score", 0.0)
        code_score = row.get("code_diff_anomaly_score", 0.0)
        meta_score = row.get("metadata_risk", 0.0)
        return alpha * msg_score + beta * code_score + gamma * meta_score
    df_merged["final_score"] = df_merged.apply(compute_final_score, axis=1)
    
    threshold = 0.6
    def classify_final(row):
        return "High Risk" if row["final_score"] > threshold else "Normal"
    df_merged["final_classification"] = df_merged.apply(classify_final, axis=1)
    
    alerts = []
    for _, row in df_merged.iterrows():
        if row["final_classification"] == "High Risk":
            alerts.append({
                "commit_sha": row["commit_sha"],
                "final_score": row["final_score"],
                "author": row.get("author", "unknown"),
                "message_risk_score": row["risk_score"],
                "code_diff_score": row["code_diff_anomaly_score"],
                "metadata_risk": row["metadata_risk"],
                "classification_phase3": row.get("classification", ""),
                "code_diff_anomaly_label": row.get("code_diff_anomaly_label", "")
            })
    
    if alerts:
        print("High Risk Commits Detected:")
        for alert in alerts:
            print(f"Commit {alert['commit_sha']} => Score {alert['final_score']:.2f} (Author: {alert['author']})")
    else:
        print("No high risk commits detected.")
    
    if output_file is not None:
        df_merged.to_json(output_file, orient="records", indent=4)
        print(f"Phase 4: Ensemble integration complete. Results saved to {output_file}")
    else:
        print("Phase 4: Ensemble integration complete (not written to file)")
    return df_merged

#############################################
# Main Pipeline with Command Line Interface
#############################################
def main():
    parser = argparse.ArgumentParser(
        description="GitHub Supply Chain Commit Analysis Tool\nRepository format: owner/repo (e.g., psf/requests)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--repo", required=True, help="GitHub repository in the format owner/repo (e.g., psf/requests)")
    parser.add_argument("--api-key", help="GitHub API key for increased rate limits")
    parser.add_argument("--days", type=int, default=90, help="Number of days to look back (default: 90)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show full output (verbose mode)")
    parser.add_argument("-w", "--write", action="store_true", help="Write full output to file")
    
    args = parser.parse_args()
    
    if args.write:
        commit_file = "github_commits.json"
        message_file = "commit_analysis.json"
        code_diff_file = "code_diff_analysis.json"
        final_file = "final_ensemble_results.json"
    else:
        commit_file = None
        message_file = None
        code_diff_file = None
        final_file = None
    
    print("Running Supply Chain Data Collection...")
    commit_data = get_commit_data(args.repo, days=args.days, output_file=commit_file, api_key=args.api_key)
    
    print("Running Commit Message Analysis...")
    message_analysis = analyze_commit_messages_from_data(commit_data, output_file=message_file)
    
    print("Running Code Diff Analysis...")
    code_diff_analysis = analyze_code_diffs_from_data(commit_data, output_file=code_diff_file)
    
    print("Running Final Ensemble Integration...")
    final_df = ensemble_analysis_from_data(message_analysis, code_diff_analysis, output_file=final_file)
    
    if args.verbose:
        print("Final Merged Output:")
        print(final_df.to_string())
    else:
        high_risk = final_df[final_df["final_classification"]=="High Risk"]
        if not high_risk.empty:
            print("High Risk Commits Detected:")
            for _, row in high_risk.iterrows():
                print(f"Commit {row['commit_sha']} => Score {row['final_score']:.2f} (Author: {row.get('author', 'unknown')})")
        else:
            print("No high risk commits detected.")
    
    print("Pipeline complete.")

if __name__ == "__main__":
    main()
