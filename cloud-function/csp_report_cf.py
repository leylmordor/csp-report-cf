from flask import Flask, request
from google.cloud import firestore
from urllib.parse import urlparse
import json
import re

app = Flask(__name__)

db = firestore.Client(database='dataStoreDBName', project='yourGCPProject')

# Define a regex pattern to match allowed origins so that you have some sort of authentication? as the CF will be public. Good to have.
allowed_origin_pattern = r"^(.*?\.)?yourDomain\.com$"

# Route to handle incoming CSP violation reports
# Entry Point for your cloud Function: csp_report
@app.route('/', methods=['POST'])
def csp_report(request):
    if request.method == 'POST':
        # Retrieve the 'Origin' header from the incoming request
        origin = request.headers.get('Origin')

        # Check if the origin matches the allowed pattern
        if origin is None or not re.match(allowed_origin_pattern, origin):
            return "Forbidden", 403
        try:
            data = json.loads(request.data)
            # Check if the data contains a 'csp-report' field
            if data and 'csp-report' in data:
                
                # Extract the domain from the CSP report
                csp_report_data = data['csp-report']
                domain = extract_domain_from_report(csp_report_data)
                
                if domain:
                    # Save the CSP report to Datastore
                    save_csp_report_to_firestore(domain, csp_report_data)

                    return f"CSP report for {domain} received and saved to Firestore.", 200
                else:
                    return "Invalid document-uri in the CSP report.", 400
            else:
                return "Invalid CSP report data in the request.", 400
        except Exception as e:
            return f"Error processing and saving CSP report: {str(e)}", 400
    else:
        return "Invalid HTTP method. Only POST requests are allowed.", 405

# Function to extract the domain from the CSP violation report
def extract_domain_from_report(report):
    document_uri = report.get('document-uri', '')
    domain = urlparse(document_uri).hostname
    return domain

# Function to save the CSP violation report to Firestore
def save_csp_report_to_firestore(domain, report_data):
    collection_ref = db.collection('csp_reports')

    new_doc_ref = collection_ref.document()
    new_doc_ref.set(report_data)

if __name__ == '__main__':
    app.run(port=5000, debug=True)
