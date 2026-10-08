import imaplib
import email
from email.header import decode_header
import re
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

def clean_header(header_val):
    if not header_val:
        return ""
    decoded_list = decode_header(header_val)
    header_str = ""
    for bytes_or_str, encoding in decoded_list:
        if isinstance(bytes_or_str, bytes):
            header_str += bytes_or_str.decode(encoding or 'utf-8', errors='ignore')
        else:
            header_str += bytes_or_str
    return header_str

def parse_email_address(raw_header):
    if not raw_header:
        return "", ""
    decoded = clean_header(raw_header)
    match = re.search(r'(.*?)(?:<([\w\.-]+@[\w\.-]+)>|$)', decoded)
    if match:
        name = match.group(1).strip('" ').strip()
        addr = match.group(2) if match.group(2) else (match.group(1) if '@' in match.group(1) else "")
        return name, addr
    return "", decoded

def extract_ip(received_headers):
    for header in received_headers:
        ips = re.findall(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', header)
        for ip in ips:
            if not ip.startswith(('10.', '172.', '192.168.', '127.')):
                return ip
    return "N/A"

def extract_auth_results(msg, key):
    auth_header = clean_header(msg.get('Authentication-Results', ''))
    if not auth_header:
        return "N/A"
    match = re.search(r'' + key + r'=(\w+)', auth_header, re.IGNORECASE)
    return match.group(1).lower() if match else "N/A"

def extract_return_path(msg):
    # 1. Try standard Return-Path header
    rp = clean_header(msg.get('Return-Path', ''))
    if rp and rp != '<>':
        match = re.search(r'<([\w\.-]+@[\w\.-]+)>', rp)
        return match.group(1) if match else rp.strip('<>')
    
    # 2. Fallback: Search in Received-SPF
    spf = clean_header(msg.get('Received-SPF', ''))
    if spf:
        match = re.search(r'envelope-from=([\w\.-]+@[\w\.-]+)', spf, re.IGNORECASE)
        if match:
            return match.group(1)
            
    # 3. Fallback: Search in Authentication-Results
    auth = clean_header(msg.get('Authentication-Results', ''))
    if auth:
        match = re.search(r'smtp\.mailfrom=([\w\.-]+@[\w\.-]+)', auth, re.IGNORECASE)
        if match:
            return match.group(1)

    return "N/A"

@app.route('/api/extract', methods=['POST'])
def extract_gmail():
    data = request.json
    gmail_user = data.get('email')
    gmail_pass = data.get('password')
    start_index = int(data.get('start', 1))  # 1-based start index (1 = newest)
    count = int(data.get('count', 10))        # Number of emails to fetch
    category = data.get('category', 'Primary')

    try:
        mail = imaplib.IMAP4_SSL('imap.gmail.com')
        mail.login(gmail_user, gmail_pass)
        
        # Select folder based on Category
        if category.lower() == 'spam':
            mail.select('[Gmail]/Spam')
            search_criterion = 'ALL'
        elif category.lower() == 'trash':
            mail.select('[Gmail]/Trash')
            search_criterion = 'ALL'
        else:
            mail.select('INBOX')
            search_criterion = f'X-GM-RAW "category:{category.lower()}"'

        status, messages = mail.search(None, search_criterion)
        
        if status != 'OK' or not messages[0]:
            mail.logout()
            return jsonify({'success': True, 'data': []})

        # email_ids ordered from OLDEST (index 0) to NEWEST (index -1)
        email_ids = messages[0].split()
        
        # Reverse list so index 0 is the NEWEST email
        email_ids.reverse()

        # Calculate exact slice
        start_offset = max(0, start_index - 1)
        end_offset = start_offset + count
        selected_ids = email_ids[start_offset:end_offset]

        results = []
        for e_id in selected_ids:
            _, msg_data = mail.fetch(e_id, '(RFC822.HEADER)')
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    
                    from_name, from_email = parse_email_address(msg.get('From'))
                    domain = from_email.split('@')[-1] if '@' in from_email else ''
                    subdomain = domain.split('.')[0] if '.' in domain else domain
                    
                    received = msg.get_all('Received') or []
                    ip_addr = extract_ip(received)
                    dkim_sig = clean_header(msg.get('DKIM-Signature', ''))
                    
                    item = {
                        'Category': category,
                        'IP': ip_addr,
                        'From Name': from_name,
                        'From Email': from_email,
                        'From Domain': domain,
                        'Subdomain': subdomain,
                        'Subject': clean_header(msg.get('Subject')),
                        'To Address': clean_header(msg.get('To')),
                        'CC Address': clean_header(msg.get('CC')),
                        'SPF Status': extract_auth_results(msg, 'spf'),
                        'DKIM Status': extract_auth_results(msg, 'dkim'),
                        'DKIM Parameters': dkim_sig[:60] + "..." if len(dkim_sig) > 60 else dkim_sig,
                        'DMARC Status': extract_auth_results(msg, 'dmarc'),
                        'Return Path': extract_return_path(msg),
                        'Message ID': clean_header(msg.get('Message-ID')),
                        'Sender': clean_header(msg.get('Sender')),
                        'Reply-To': clean_header(msg.get('Reply-To')),
                        'In Reply To': clean_header(msg.get('In-Reply-To')),
                        'Content Type': clean_header(msg.get('Content-Type')),
                        'MIME Version': clean_header(msg.get('MIME-Version')),
                        'List ID': clean_header(msg.get('List-ID')),
                        'List Unsubscribe': clean_header(msg.get('List-Unsubscribe')),
                        'Feedback ID': clean_header(msg.get('Feedback-ID')),
                        'Full Email': f"{from_name} <{from_email}>"
                    }
                    results.append(item)

        mail.logout()
        return jsonify({'success': True, 'data': results})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    app.run(port=5000, debug=True)