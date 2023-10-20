# CSP Violation Reports Processor

This project consists of Python scripts that facilitate the collection and processing of Content Security Policy (CSP) violation reports. 
The system is comprised of two components: 
- Cloud Function for receiving and storing CSP violation reports
- Python script for generating CSP policies based on these reports.

## Cloud Function for Receiving and Storing CSP Violation Reports

The provided Python script sets up a Flask-based Cloud Function to receive and store CSP violation reports in Google Firestore. 
```bash
git clone git@github.com:leylmordor/csp-report-cf.git && cd csp-report-cf/cloud-function
```
```bash
gcloud functions deploy yourCFName --project=yourGCPProject\
--region=us-central1 \
--runtime=python39 --entry-point=csp_report --trigger-http \
--allow-unauthenticated --security-level=secure-always
```

### Config
1. Initialize your Firestore client and set up the Firestore database with the appropriate name.

```python
db = firestore.Client(database='yourDatabaseName', project='yourProject')
```

### Create your firestore DB
```bash
gcloud alpha firestore --project yourGCPproject databases create \
--database=yourDBName \
--location=nam5 \
--type=firestore-native \
[--delete-protection]
```

## Generate CSP
Just run the file named `generate_csp.py` and it will generate the CSP report for you.

# Thank you! hope this helps
