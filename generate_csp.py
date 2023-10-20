from google.cloud import firestore
from urllib.parse import urlparse

db = firestore.Client(database='dataStoreDBName', project='yourGCPProject')

# Empty list to store CSP violatio
csp_reports = []

# Get a ref to the 'csp_reports' collection in Firestore
reports_collection = db.collection('yourCollection')

# Retrieve all documents from the 'csp_reports' collection
reports_documents = reports_collection.stream()

# Initialize a dictionary to store CSP policies by domain
csp_by_domain = {}

# Iterate through each document in the 'csp_reports' collection
for doc in reports_documents:
    # Convert to a dictionary
    report = doc.to_dict()

    # Extract the 'document-uri'
    document_uri = report.get('document-uri')

    if document_uri:
        # Parse 'document-uri' to get the hostname
        parsed_uri = urlparse(document_uri)
        hostname = parsed_uri.netloc

        # Create an initial CSP policy for just incase
        if hostname not in csp_by_domain:
            csp_by_domain[hostname] = {
                'default-src': ["'self'"],
                'script-src': ["'self'"],
                'style-src': ["'self'"],
                'connect-src': ["'self'"],
                'font-src': ["'self'"],
                'frame-src': ["'self'"],
                'img-src': ["'self'"],
                'manifest-src': ["'self'"],
                'media-src': ["'self'"],
                'frame-ancestors': ["'none'"],
                'report-uri': ["https://your-cloud-function-url"],
            }

        # Extract the 'violated-directive' and 'blocked-uri' fields from the CSP violation report
        directive = report['violated-directive']
        blocked_uri = report['blocked-uri']

        # If the directive is in the CSP policy, add the blocked URI to it
        if directive in csp_by_domain[hostname]:
            if blocked_uri:
                parsed_blocked_uri = urlparse(blocked_uri)
                blocked_hostname = parsed_blocked_uri.netloc
                if blocked_hostname not in csp_by_domain[hostname][directive]:
                    csp_by_domain[hostname][directive].append(blocked_hostname)

# Iterate through the generated CSP policies for each domain
for domain, directives in csp_by_domain.items():
    csp = ''
    for directive, values in directives.items():
        csp += f'{directive} {(" ".join(values)).strip()}; '
    csp = csp.strip()

    print(f"Generated CSP for domain {domain}:\n")
    print(csp)
