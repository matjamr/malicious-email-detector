#!/usr/bin/env python3
"""
End-to-End Evaluation Script for Email Spam Detection API

This script:
1. Downloads the phishing email dataset from Kaggle
2. Loads and parses the dataset
3. Sends emails to the API for analysis
4. Evaluates the results against ground truth labels
5. Generates comprehensive performance metrics and reports
"""

import os
import sys
import json
import csv
import time
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from collections import defaultdict
import requests
import kagglehub
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_auc_score,
    roc_curve
)
import matplotlib.pyplot as plt
import seaborn as sns

# Configuration
API_BASE_URL = "http://localhost:5000"
DATASET_NAME = "naserabdullahalam/phishing-email-dataset"
SCORE_THRESHOLD = 50  # Emails with score >= threshold are considered spam/phishing
MAX_SAMPLES = None  # Set to None to test all, or a number to limit (e.g., 100)
REQUEST_DELAY = 0.1  # Delay between API requests (seconds)


class DatasetLoader:
    """Load and parse the phishing email dataset"""
    
    def __init__(self, dataset_path: Path):
        self.dataset_path = dataset_path
        self.emails = []
        
    def load(self) -> List[Dict[str, Any]]:
        """Load dataset from various formats (CSV, JSON, etc.)"""
        print(f"Loading dataset from: {self.dataset_path}")
        
        # Try different file formats
        csv_files = list(self.dataset_path.glob("*.csv"))
        json_files = list(self.dataset_path.glob("*.json"))
        
        if csv_files:
            print(f"Found CSV files: {[f.name for f in csv_files]}")
            return self._load_csv(csv_files[0])
        elif json_files:
            print(f"Found JSON files: {[f.name for f in json_files]}")
            return self._load_json(json_files[0])
        else:
            # Try to find any data files
            all_files = list(self.dataset_path.rglob("*"))
            data_files = [f for f in all_files if f.is_file() and not f.name.startswith('.')]
            print(f"Found {len(data_files)} files in dataset directory")
            
            # Try to load as CSV or JSON from any file
            for file_path in data_files:
                try:
                    if file_path.suffix.lower() == '.csv':
                        return self._load_csv(file_path)
                    elif file_path.suffix.lower() == '.json':
                        return self._load_json(file_path)
                except Exception as e:
                    print(f"Error loading {file_path}: {e}")
                    continue
            
            raise ValueError(f"Could not find or parse dataset files in {self.dataset_path}")
    
    def _load_csv(self, csv_path: Path) -> List[Dict[str, Any]]:
        """Load dataset from CSV file"""
        print(f"Loading CSV from: {csv_path}")
        
        # Try pandas first (handles various CSV formats well)
        try:
            df = pd.read_csv(csv_path, encoding='utf-8')
            print(f"Loaded {len(df)} rows, columns: {list(df.columns)}")
            
            emails = []
            for _, row in df.iterrows():
                email = self._parse_row(row.to_dict())
                if email:
                    emails.append(email)
            return emails
        except Exception as e:
            print(f"Pandas read failed: {e}, trying manual CSV parsing...")
            # Fallback to manual CSV parsing
            return self._load_csv_manual(csv_path)
    
    def _load_csv_manual(self, csv_path: Path) -> List[Dict[str, Any]]:
        """Manual CSV loading with encoding detection"""
        emails = []
        encodings = ['utf-8', 'latin-1', 'iso-8859-1', 'cp1252']
        
        for encoding in encodings:
            try:
                with open(csv_path, 'r', encoding=encoding, errors='replace') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        email = self._parse_row(row)
                        if email:
                            emails.append(email)
                print(f"Successfully loaded {len(emails)} emails with {encoding} encoding")
                return emails
            except Exception as e:
                print(f"Failed with {encoding}: {e}")
                continue
        
        raise ValueError(f"Could not read CSV with any encoding")
    
    def _load_json(self, json_path: Path) -> List[Dict[str, Any]]:
        """Load dataset from JSON file"""
        print(f"Loading JSON from: {json_path}")
        
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Handle different JSON structures
        if isinstance(data, list):
            emails = [self._parse_row(item) for item in data if self._parse_row(item)]
        elif isinstance(data, dict):
            # Check for common keys
            if 'emails' in data:
                emails = [self._parse_row(item) for item in data['emails'] if self._parse_row(item)]
            elif 'data' in data:
                emails = [self._parse_row(item) for item in data['data'] if self._parse_row(item)]
            else:
                emails = [self._parse_row(data)]
        else:
            emails = []
        
        print(f"Loaded {len(emails)} emails from JSON")
        return emails
    
    def _parse_row(self, row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse a row into email format expected by API"""
        # Common column name variations
        subject_key = self._find_key(row, ['subject', 'Subject', 'SUBJECT', 'email_subject', 'title'])
        body_key = self._find_key(row, ['body', 'Body', 'BODY', 'content', 'Content', 'text', 'Text', 'message'])
        from_key = self._find_key(row, ['from', 'From', 'FROM', 'sender', 'Sender', 'from_address'])
        to_key = self._find_key(row, ['to', 'To', 'TO', 'recipient', 'Recipient', 'to_address'])
        label_key = self._find_key(row, ['label', 'Label', 'LABEL', 'class', 'Class', 'CLASS', 
                                         'type', 'Type', 'TYPE', 'category', 'Category', 
                                         'is_phishing', 'is_spam', 'phishing', 'spam'])
        
        # Build email dict
        email = {
            'subject': row.get(subject_key, '') if subject_key else '',
            'body': row.get(body_key, '') if body_key else '',
            'from': row.get(from_key, 'unknown@example.com') if from_key else 'unknown@example.com',
            'to': row.get(to_key, 'user@example.com') if to_key else 'user@example.com',
        }
        
        # Parse label (handle different formats: 0/1, spam/ham, phishing/legitimate, True/False, etc.)
        label = None
        if label_key:
            label_val = row.get(label_key)
            if label_val is not None:
                label = self._normalize_label(label_val)
        
        # Only return if we have at least subject or body
        if email['subject'] or email['body']:
            email['label'] = label
            return email
        
        return None
    
    def _find_key(self, row: Dict[str, Any], possible_keys: List[str]) -> Optional[str]:
        """Find the first matching key in row (case-insensitive)"""
        row_keys_lower = {k.lower(): k for k in row.keys()}
        for key in possible_keys:
            if key.lower() in row_keys_lower:
                return row_keys_lower[key.lower()]
        return None
    
    def _normalize_label(self, label: Any) -> int:
        """Normalize label to 0 (ham/legitimate) or 1 (spam/phishing)"""
        if isinstance(label, bool):
            return 1 if label else 0
        if isinstance(label, (int, float)):
            return 1 if int(label) == 1 or int(label) > 0 else 0
        if isinstance(label, str):
            label_lower = label.lower().strip()
            # Phishing/spam indicators
            if label_lower in ['1', 'true', 'yes', 'spam', 'phishing', 'malicious', 'bad']:
                return 1
            # Legitimate indicators
            elif label_lower in ['0', 'false', 'no', 'ham', 'legitimate', 'benign', 'good', 'safe']:
                return 0
        return 0  # Default to legitimate if unclear


class APIClient:
    """Client for interacting with the email analysis API"""
    
    def __init__(self, base_url: str = API_BASE_URL):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({'Content-Type': 'application/json'})
    
    def health_check(self) -> bool:
        """Check if API is healthy"""
        try:
            response = self.session.get(f"{self.base_url}/health", timeout=5)
            return response.status_code == 200
        except Exception as e:
            print(f"Health check failed: {e}")
            return False
    
    def analyze_email(self, email: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Send email for analysis and return response"""
        try:
            # Prepare request payload (exclude label if present)
            payload = {k: v for k, v in email.items() if k != 'label'}
            
            response = self.session.post(
                f"{self.base_url}/analyze",
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"API error {response.status_code}: {response.text}")
                return None
        except Exception as e:
            print(f"Error analyzing email: {e}")
            return None


class Evaluator:
    """Evaluate API performance against ground truth"""
    
    def __init__(self, score_threshold: int = SCORE_THRESHOLD):
        self.score_threshold = score_threshold
        self.predictions = []
        self.true_labels = []
        self.scores = []
        self.results = []
    
    def add_result(self, true_label: int, api_response: Dict[str, Any]) -> None:
        """Add a single result for evaluation"""
        if api_response is None:
            return
        
        score = api_response.get('overall_score', 0)
        predicted_label = 1 if score >= self.score_threshold else 0
        
        self.predictions.append(predicted_label)
        self.true_labels.append(true_label)
        self.scores.append(score)
        
        self.results.append({
            'true_label': true_label,
            'predicted_label': predicted_label,
            'score': score,
            'response': api_response
        })
    
    def evaluate(self) -> Dict[str, Any]:
        """Calculate all evaluation metrics"""
        if len(self.true_labels) == 0:
            return {"error": "No results to evaluate"}
        
        # Basic metrics
        accuracy = accuracy_score(self.true_labels, self.predictions)
        precision = precision_score(self.true_labels, self.predictions, zero_division=0)
        recall = recall_score(self.true_labels, self.predictions, zero_division=0)
        f1 = f1_score(self.true_labels, self.predictions, zero_division=0)
        
        # Confusion matrix
        cm = confusion_matrix(self.true_labels, self.predictions)
        # Handle different confusion matrix sizes
        if cm.size == 4:
            tn, fp, fn, tp = cm.ravel()
        elif cm.size == 1:
            # Only one class present
            if self.true_labels[0] == 0:
                tn, fp, fn, tp = (len(self.true_labels), 0, 0, 0)
            else:
                tn, fp, fn, tp = (0, 0, 0, len(self.true_labels))
        else:
            tn, fp, fn, tp = (0, 0, 0, 0)
        
        # Additional metrics
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
        sensitivity = recall  # Same as recall
        
        # ROC AUC (if we have scores)
        try:
            auc = roc_auc_score(self.true_labels, self.scores) if len(set(self.true_labels)) > 1 else 0.0
        except:
            auc = 0.0
        
        # Score statistics by class
        spam_scores = [s for s, l in zip(self.scores, self.true_labels) if l == 1]
        ham_scores = [s for s, l in zip(self.scores, self.true_labels) if l == 0]
        
        metrics = {
            'total_samples': len(self.true_labels),
            'spam_samples': sum(self.true_labels),
            'ham_samples': len(self.true_labels) - sum(self.true_labels),
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'specificity': specificity,
            'sensitivity': sensitivity,
            'auc': auc,
            'confusion_matrix': {
                'true_negative': int(tn),
                'false_positive': int(fp),
                'false_negative': int(fn),
                'true_positive': int(tp)
            },
            'score_statistics': {
                'spam': {
                    'mean': float(sum(spam_scores) / len(spam_scores)) if spam_scores else 0,
                    'std': float(pd.Series(spam_scores).std()) if len(spam_scores) > 1 else 0,
                    'min': float(min(spam_scores)) if spam_scores else 0,
                    'max': float(max(spam_scores)) if spam_scores else 0
                },
                'ham': {
                    'mean': float(sum(ham_scores) / len(ham_scores)) if ham_scores else 0,
                    'std': float(pd.Series(ham_scores).std()) if len(ham_scores) > 1 else 0,
                    'min': float(min(ham_scores)) if ham_scores else 0,
                    'max': float(max(ham_scores)) if ham_scores else 0
                }
            },
            'threshold': self.score_threshold
        }
        
        return metrics
    
    def generate_report(self, metrics: Dict[str, Any], output_dir: Path) -> None:
        """Generate detailed evaluation report"""
        report_path = output_dir / "evaluation_report.txt"
        
        with open(report_path, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("EMAIL SPAM DETECTION API - EVALUATION REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n")
            f.write(f"Score Threshold: {metrics.get('threshold', SCORE_THRESHOLD)}\n\n")
            
            f.write("-" * 80 + "\n")
            f.write("DATASET SUMMARY\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total Samples: {metrics.get('total_samples', 0)}\n")
            f.write(f"Spam/Phishing Samples: {metrics.get('spam_samples', 0)}\n")
            f.write(f"Legitimate (Ham) Samples: {metrics.get('ham_samples', 0)}\n\n")
            
            f.write("-" * 80 + "\n")
            f.write("PERFORMANCE METRICS\n")
            f.write("-" * 80 + "\n")
            f.write(f"Accuracy:  {metrics.get('accuracy', 0):.4f} ({metrics.get('accuracy', 0)*100:.2f}%)\n")
            f.write(f"Precision: {metrics.get('precision', 0):.4f} ({metrics.get('precision', 0)*100:.2f}%)\n")
            f.write(f"Recall:    {metrics.get('recall', 0):.4f} ({metrics.get('recall', 0)*100:.2f}%)\n")
            f.write(f"F1 Score:  {metrics.get('f1_score', 0):.4f}\n")
            f.write(f"Specificity: {metrics.get('specificity', 0):.4f} ({metrics.get('specificity', 0)*100:.2f}%)\n")
            f.write(f"Sensitivity: {metrics.get('sensitivity', 0):.4f} ({metrics.get('sensitivity', 0)*100:.2f}%)\n")
            f.write(f"AUC-ROC:   {metrics.get('auc', 0):.4f}\n\n")
            
            f.write("-" * 80 + "\n")
            f.write("CONFUSION MATRIX\n")
            f.write("-" * 80 + "\n")
            cm = metrics.get('confusion_matrix', {})
            f.write(f"                    Predicted\n")
            f.write(f"                  Ham    Spam\n")
            f.write(f"Actual  Ham      {cm.get('true_negative', 0):4d}   {cm.get('false_positive', 0):4d}\n")
            f.write(f"        Spam     {cm.get('false_negative', 0):4d}   {cm.get('true_positive', 0):4d}\n\n")
            
            f.write("-" * 80 + "\n")
            f.write("SCORE STATISTICS\n")
            f.write("-" * 80 + "\n")
            spam_stats = metrics.get('score_statistics', {}).get('spam', {})
            ham_stats = metrics.get('score_statistics', {}).get('ham', {})
            f.write(f"Spam/Phishing Scores:\n")
            f.write(f"  Mean: {spam_stats.get('mean', 0):.2f}\n")
            f.write(f"  Std:  {spam_stats.get('std', 0):.2f}\n")
            f.write(f"  Min:  {spam_stats.get('min', 0):.2f}\n")
            f.write(f"  Max:  {spam_stats.get('max', 0):.2f}\n\n")
            f.write(f"Legitimate (Ham) Scores:\n")
            f.write(f"  Mean: {ham_stats.get('mean', 0):.2f}\n")
            f.write(f"  Std:  {ham_stats.get('std', 0):.2f}\n")
            f.write(f"  Min:  {ham_stats.get('min', 0):.2f}\n")
            f.write(f"  Max:  {ham_stats.get('max', 0):.2f}\n\n")
            
            f.write("-" * 80 + "\n")
            f.write("CLASSIFICATION REPORT\n")
            f.write("-" * 80 + "\n")
            report = classification_report(
                self.true_labels,
                self.predictions,
                target_names=['Ham', 'Spam'],
                zero_division=0
            )
            f.write(report + "\n")
        
        print(f"\nReport saved to: {report_path}")
    
    def plot_results(self, metrics: Dict[str, Any], output_dir: Path) -> None:
        """Generate visualization plots"""
        try:
            # Confusion Matrix Heatmap
            fig, axes = plt.subplots(1, 2, figsize=(14, 5))
            
            # Confusion Matrix
            cm = metrics.get('confusion_matrix', {})
            cm_matrix = [[cm.get('true_negative', 0), cm.get('false_positive', 0)],
                        [cm.get('false_negative', 0), cm.get('true_positive', 0)]]
            
            sns.heatmap(cm_matrix, annot=True, fmt='d', cmap='Blues', 
                       xticklabels=['Ham', 'Spam'], yticklabels=['Ham', 'Spam'],
                       ax=axes[0], cbar_kws={'label': 'Count'})
            axes[0].set_title('Confusion Matrix')
            axes[0].set_ylabel('True Label')
            axes[0].set_xlabel('Predicted Label')
            
            # Score Distribution
            spam_scores = [s for s, l in zip(self.scores, self.true_labels) if l == 1]
            ham_scores = [s for s, l in zip(self.scores, self.true_labels) if l == 0]
            
            axes[1].hist(ham_scores, bins=20, alpha=0.7, label='Ham', color='green', edgecolor='black')
            axes[1].hist(spam_scores, bins=20, alpha=0.7, label='Spam', color='red', edgecolor='black')
            axes[1].axvline(SCORE_THRESHOLD, color='black', linestyle='--', linewidth=2, label=f'Threshold ({SCORE_THRESHOLD})')
            axes[1].set_xlabel('Risk Score')
            axes[1].set_ylabel('Frequency')
            axes[1].set_title('Score Distribution by Class')
            axes[1].legend()
            axes[1].grid(True, alpha=0.3)
            
            plt.tight_layout()
            plot_path = output_dir / "evaluation_plots.png"
            plt.savefig(plot_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            print(f"Plots saved to: {plot_path}")
        except Exception as e:
            print(f"Warning: Could not generate plots: {e}")


def main():
    parser = argparse.ArgumentParser(description='E2E Evaluation of Email Spam Detection API')
    parser.add_argument('--api-url', type=str, default=API_BASE_URL, help='API base URL')
    parser.add_argument('--threshold', type=int, default=SCORE_THRESHOLD, help='Score threshold for classification')
    parser.add_argument('--max-samples', type=int, default=MAX_SAMPLES, help='Maximum number of samples to test')
    parser.add_argument('--delay', type=float, default=REQUEST_DELAY, help='Delay between API requests (seconds)')
    parser.add_argument('--output-dir', type=str, default='e2e_results', help='Output directory for results')
    parser.add_argument('--skip-download', action='store_true', help='Skip dataset download (use existing)')
    
    args = parser.parse_args()
    
    # Setup
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)
    
    print("=" * 80)
    print("EMAIL SPAM DETECTION API - END-TO-END EVALUATION")
    print("=" * 80)
    print(f"API URL: {args.api_url}")
    print(f"Score Threshold: {args.threshold}")
    print(f"Max Samples: {args.max_samples or 'All'}")
    print(f"Output Directory: {output_dir}")
    print("=" * 80 + "\n")
    
    # Step 1: Download dataset
    if not args.skip_download:
        print("Step 1: Downloading dataset from Kaggle...")
        try:
            dataset_path = kagglehub.dataset_download(DATASET_NAME)
            print(f"Dataset downloaded to: {dataset_path}\n")
        except Exception as e:
            print(f"Error downloading dataset: {e}")
            print("Trying to use existing dataset directory...")
            # Try common locations
            possible_paths = [
                Path.home() / ".cache" / "kagglehub" / "datasets" / "naserabdullahalam" / "phishing-email-dataset",
                Path(".") / "dataset",
                Path(".") / "data"
            ]
            dataset_path = None
            for path in possible_paths:
                if path.exists():
                    dataset_path = path
                    break
            if not dataset_path:
                print("ERROR: Could not find dataset. Please download it first.")
                return 1
    else:
        # Find existing dataset
        possible_paths = [
            Path.home() / ".cache" / "kagglehub" / "datasets" / "naserabdullahalam" / "phishing-email-dataset",
            Path(".") / "dataset",
            Path(".") / "data"
        ]
        dataset_path = None
        for path in possible_paths:
            if path.exists():
                dataset_path = path
                break
        if not dataset_path:
            print("ERROR: Could not find dataset. Use --skip-download=false to download.")
            return 1
    
    # Step 2: Load dataset
    print("Step 2: Loading dataset...")
    loader = DatasetLoader(Path(dataset_path))
    try:
        emails = loader.load()
        print(f"Loaded {len(emails)} emails from dataset\n")
    except Exception as e:
        print(f"ERROR: Failed to load dataset: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    # Filter emails with labels
    emails_with_labels = [e for e in emails if e.get('label') is not None]
    if len(emails_with_labels) == 0:
        print("WARNING: No emails with labels found. Creating synthetic labels for testing...")
        # Assign labels based on some heuristic (e.g., suspicious keywords)
        for email in emails:
            subject = email.get('subject', '').lower()
            body = email.get('body', '').lower()
            suspicious = any(kw in subject or kw in body for kw in 
                           ['urgent', 'click', 'winner', 'prize', 'verify', 'suspended'])
            email['label'] = 1 if suspicious else 0
        emails_with_labels = emails
    
    # Limit samples if requested
    if args.max_samples and len(emails_with_labels) > args.max_samples:
        print(f"Limiting to {args.max_samples} samples...")
        emails_with_labels = emails_with_labels[:args.max_samples]
    
    print(f"Testing with {len(emails_with_labels)} emails (with labels)\n")
    
    # Step 3: Check API health
    print("Step 3: Checking API health...")
    client = APIClient(args.api_url)
    if not client.health_check():
        print(f"ERROR: API at {args.api_url} is not healthy. Please start the backend server.")
        return 1
    print("API is healthy!\n")
    
    # Step 4: Evaluate
    print("Step 4: Sending emails to API for analysis...")
    evaluator = Evaluator(score_threshold=args.threshold)
    
    successful = 0
    failed = 0
    
    for i, email in enumerate(emails_with_labels, 1):
        if i % 10 == 0:
            print(f"  Processed {i}/{len(emails_with_labels)} emails...")
        
        label = email.get('label', 0)
        response = client.analyze_email(email)
        
        if response:
            evaluator.add_result(label, response)
            successful += 1
        else:
            failed += 1
        
        # Rate limiting
        if args.delay > 0:
            time.sleep(args.delay)
    
    print(f"\nCompleted: {successful} successful, {failed} failed\n")
    
    # Step 5: Calculate metrics
    print("Step 5: Calculating evaluation metrics...")
    metrics = evaluator.evaluate()
    
    if 'error' in metrics:
        print(f"ERROR: {metrics['error']}")
        return 1
    
    # Step 6: Generate reports
    print("Step 6: Generating reports and visualizations...")
    evaluator.generate_report(metrics, output_dir)
    evaluator.plot_results(metrics, output_dir)
    
    # Save metrics as JSON
    metrics_path = output_dir / "metrics.json"
    with open(metrics_path, 'w') as f:
        json.dump(metrics, f, indent=2)
    print(f"Metrics saved to: {metrics_path}\n")
    
    # Print summary
    print("=" * 80)
    print("EVALUATION SUMMARY")
    print("=" * 80)
    print(f"Total Samples: {metrics['total_samples']}")
    print(f"Accuracy:  {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
    print(f"Precision: {metrics['precision']:.4f} ({metrics['precision']*100:.2f}%)")
    print(f"Recall:    {metrics['recall']:.4f} ({metrics['recall']*100:.2f}%)")
    print(f"F1 Score:  {metrics['f1_score']:.4f}")
    print(f"AUC-ROC:   {metrics['auc']:.4f}")
    print("=" * 80)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
