import re
import json
import os
from datetime import datetime
from pathlib import Path
from google.genai import types

class PIIScanner:
    def __init__(self):
        self.patterns = {
            'ssn': {
                'regex': r'\b(?:\d{3}[-\s]\d{2}[-\s]\d{4}|\d{9})\b',
                'description': 'Social Security Number',
                'confidence': 'high'
            },
            'credit_card': {
                'regex': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
                'description': 'Credit Card Number',
                'confidence': 'high'
            },
            'email': {
                'regex': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'description': 'Email Address',
                'confidence': 'medium'
            },
            'phone_us': {
                'regex': r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b',
                'description': 'US Phone Number',
                'confidence': 'medium'
            },
            'ip_address': {
                'regex': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                'description': 'IP Address',
                'confidence': 'low'
            },
            'driver_license': {
                'regex': r'\b[A-Z]{1,2}[0-9]{6,8}\b',
                'description': 'Driver License (Generic)',
                'confidence': 'medium'
            },
            'passport': {
                'regex': r'\b[A-Z]{1,2}[0-9]{6,9}\b',
                'description': 'Passport Number (Generic)',
                'confidence': 'medium'
            },
            'bank_account': {
                'regex': r'\b(?<![0-9])[0-9]{10,17}(?![0-9])\b',
                'description': 'Bank Account Number',
                'confidence': 'low'
            },
            'routing_number': {
                'regex': r'\b[0-9]{9}\b',
                'description': 'Bank Routing Number',
                'confidence': 'medium'
            },
            'date_of_birth': {
                'regex': r'\b(?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12][0-9]|3[01])[/-](?:19|20)[0-9]{2}\b',
                'description': 'Date of Birth',
                'confidence': 'medium'
            },
            'medicare_number': {
                'regex': r'\b[0-9]{3}-[0-9]{2}-[0-9]{4}-[A-Z]{1,2}\b',
                'description': 'Medicare Number',
                'confidence': 'high'
            },
            'ein': {
                'regex': r'\b[0-9]{2}-[0-9]{7}\b',
                'description': 'Employer Identification Number',
                'confidence': 'high'
            },
            'iban': {
                'regex': r'\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b',
                'description': 'International Bank Account Number',
                'confidence': 'high'
            },
            'mac_address': {
                'regex': r'\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b',
                'description': 'MAC Address',
                'confidence': 'low'
            },
            'aadhar': {
                'regex': r'\b(?:\d{4}[-\s]?\d{4}[-\s]?\d{4}|\d{12})\b',
                'description': 'Indian Aadhar Number',
                'confidence': 'high'
            },
            'phone_india': {
                'regex': r'\b(?:\+91[-.\s]?|91[-.\s]?|0)?(?:[6-9]\d{9}|[1-9]\d{2}[-.\s]?\d{3}[-.\s]?\d{4})\b',
                'description': 'Indian Phone Number',
                'confidence': 'medium'
            }
        }
        
        self.high_priority_patterns = ['ssn', 'credit_card', 'aadhar']
        self.exclusion_patterns = {
            'bank_account': ['credit_card', 'ssn', 'aadhar', 'routing_number']
        }

        self.whitelist_patterns = [
            r'000-00-0000',
            r'111-11-1111',
            r'example@example\.com',
            r'test@test\.com',
            r'127\.0\.0\.1',
            r'192\.168\.',
            r'10\.0\.',
            r'172\.16\.',
            r'0000[-\s]?0000[-\s]?0000',
            r'1111[-\s]?1111[-\s]?1111',
            r'\+91[-.\s]?9999999999',
            r'0123456789'
        ]

    def validate_indian_phone(self, phone):
        clean_phone = re.sub(r'[^0-9]', '', phone)
        
        if clean_phone.startswith('91'):
            clean_phone = clean_phone[2:]
        elif clean_phone.startswith('0'):
            clean_phone = clean_phone[1:]
        
        if len(clean_phone) != 10:
            return False
        
        if not clean_phone[0] in '6789':
            return False
        
        if len(set(clean_phone)) == 1:
            return False
        
        invalid_patterns = [
            '0000000000', '1111111111', '2222222222', '3333333333',
            '4444444444', '5555555555', '6666666666', '7777777777',
            '8888888888', '9999999999', '1234567890', '0123456789'
        ]
        
        if clean_phone in invalid_patterns:
            return False
        
        return True

    def validate_aadhar(self, aadhar):
        clean_aadhar = re.sub(r'[^0-9]', '', aadhar)
        
        if len(clean_aadhar) != 12:
            return False
        
        if clean_aadhar.startswith('0') or clean_aadhar.startswith('1'):
            return False
        
        if len(set(clean_aadhar)) <= 2:
            return False
        
        return True

    def luhn_check(self, number):
        digits = [int(d) for d in str(number) if d.isdigit()]
        checksum = 0
        reverse_digits = digits[::-1]
        
        for i, digit in enumerate(reverse_digits):
            if i % 2 == 1:
                digit *= 2
                if digit > 9:
                    digit -= 9
            checksum += digit
        
        return checksum % 10 == 0

    def validate_credit_card(self, number):
        clean_number = re.sub(r'[^0-9]', '', number)
        if len(clean_number) < 13 or len(clean_number) > 19:
            return False
        return self.luhn_check(clean_number)

    def validate_ssn(self, ssn):
        clean_ssn = re.sub(r'[^0-9]', '', ssn)
        if len(clean_ssn) != 9:
            return False
        
        if clean_ssn in ['000000000', '111111111', '222222222', '333333333', '444444444', '555555555', '666666666', '777777777', '888888888', '999999999']:
            return False
        
        if clean_ssn.startswith('000') or clean_ssn[3:5] == '00' or clean_ssn[5:9] == '0000':
            return False
        
        return True

    def is_whitelisted(self, text):
        for pattern in self.whitelist_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def scan_text(self, text, validate=True):
        findings = []
        found_values = set()
        
        for pii_type, pattern_info in self.patterns.items():
            matches = re.findall(pattern_info['regex'], text, re.IGNORECASE)
            
            for match in matches:
                if isinstance(match, tuple):
                    match_text = ''.join(match)
                else:
                    match_text = match
                
                if self.is_whitelisted(match_text):
                    continue
                
                should_exclude = False
                if pii_type in self.exclusion_patterns:
                    for exclusion_type in self.exclusion_patterns[pii_type]:
                        exclusion_pattern = self.patterns[exclusion_type]['regex']
                        if re.search(exclusion_pattern, match_text, re.IGNORECASE):
                            should_exclude = True
                            break
                
                if should_exclude:
                    continue
                
                is_valid = True
                if validate:
                    if pii_type == 'credit_card':
                        is_valid = self.validate_credit_card(match_text)
                    elif pii_type == 'ssn':
                        is_valid = self.validate_ssn(match_text)
                    elif pii_type == 'aadhar':
                        is_valid = self.validate_aadhar(match_text)
                    elif pii_type == 'phone_india':
                        is_valid = self.validate_indian_phone(match_text)
                
                if is_valid:
                    unique_key = f"{pii_type}:{match_text}"
                    if unique_key not in found_values:
                        found_values.add(unique_key)
                        finding = {
                            'type': pii_type,
                            'value': match_text,
                            'description': pattern_info['description'],
                            'confidence': pattern_info['confidence'],
                            'position': text.find(match_text),
                            'validated': validate and pii_type in ['credit_card', 'ssn', 'aadhar', 'phone_india']
                        }
                        findings.append(finding)
        
        return findings

    def scan_file(self, filepath, encoding='utf-8'):
        result = {
            'filepath': filepath,
            'scan_time': datetime.now().isoformat(),
            'file_size': 0,
            'findings': [],
            'summary': {},
            'errors': []
        }
        
        try:
            stat = os.stat(filepath)
            result['file_size'] = stat.st_size
            result['file_modified'] = datetime.fromtimestamp(stat.st_mtime).isoformat()
            
            with open(filepath, 'r', encoding=encoding, errors='ignore') as f:
                content = f.read()
            
            findings = self.scan_text(content)
            result['findings'] = findings
            
            summary = {}
            for finding in findings:
                pii_type = finding['type']
                if pii_type not in summary:
                    summary[pii_type] = {
                        'count': 0,
                        'confidence_levels': {},
                        'description': finding['description']
                    }
                summary[pii_type]['count'] += 1
                confidence = finding['confidence']
                if confidence not in summary[pii_type]['confidence_levels']:
                    summary[pii_type]['confidence_levels'][confidence] = 0
                summary[pii_type]['confidence_levels'][confidence] += 1
            
            result['summary'] = summary
            result['total_findings'] = len(findings)
            result['high_confidence_findings'] = len([f for f in findings if f['confidence'] == 'high'])
            
        except Exception as e:
            result['errors'].append(str(e))
        
        return result

    def scan_directory(self, directory_path, recursive=True, file_extensions=None):
        if file_extensions is None:
            file_extensions = ['.txt', '.log', '.csv', '.json', '.xml', '.sql', '.py', '.js', '.php']
        
        results = {
            'directory': directory_path,
            'scan_time': datetime.now().isoformat(),
            'files_scanned': 0,
            'files_with_pii': 0,
            'total_findings': 0,
            'file_results': [],
            'summary': {}
        }
        
        try:
            path_obj = Path(directory_path)
            
            if recursive:
                files = path_obj.rglob('*')
            else:
                files = path_obj.iterdir()
            
            for file_path in files:
                if file_path.is_file() and file_path.suffix.lower() in file_extensions:
                    file_result = self.scan_file(str(file_path))
                    results['file_results'].append(file_result)
                    results['files_scanned'] += 1
                    
                    if file_result['total_findings'] > 0:
                        results['files_with_pii'] += 1
                        results['total_findings'] += file_result['total_findings']
            
            overall_summary = {}
            for file_result in results['file_results']:
                for pii_type, summary_data in file_result['summary'].items():
                    if pii_type not in overall_summary:
                        overall_summary[pii_type] = {
                            'total_count': 0,
                            'files_found_in': 0,
                            'description': summary_data['description']
                        }
                    overall_summary[pii_type]['total_count'] += summary_data['count']
                    overall_summary[pii_type]['files_found_in'] += 1
            
            results['summary'] = overall_summary
            
        except Exception as e:
            results['error'] = str(e)
        
        return results

    def generate_report(self, scan_results, output_format='json'):
        if output_format == 'json':
            return json.dumps(scan_results, indent=2)
        elif output_format == 'summary':
            report = f"PII Scan Report\n"
            report += f"================\n"
            report += f"Scan Time: {scan_results.get('scan_time', 'Unknown')}\n"
            
            if 'directory' in scan_results:
                report += f"Directory: {scan_results['directory']}\n"
                report += f"Files Scanned: {scan_results['files_scanned']}\n"
                report += f"Files with PII: {scan_results['files_with_pii']}\n"
                report += f"Total Findings: {scan_results['total_findings']}\n\n"
                
                for pii_type, data in scan_results.get('summary', {}).items():
                    report += f"{data['description']}: {data['total_count']} instances in {data['files_found_in']} files\n"
            else:
                report += f"File: {scan_results['filepath']}\n"
                report += f"Total Findings: {scan_results['total_findings']}\n"
                report += f"High Confidence: {scan_results['high_confidence_findings']}\n\n"
                
                for pii_type, data in scan_results.get('summary', {}).items():
                    report += f"{data['description']}: {data['count']} instances\n"
            
            return report

    def save_results(self, results, output_file, format='json'):
        try:
            with open(output_file, 'w') as f:
                if format == 'json':
                    json.dump(results, f, indent=2)
                else:
                    f.write(self.generate_report(results, format))
            return True
        except Exception as e:
            return False

scanner = PIIScanner()

def scan_text_for_pii(text, validate=True):
    return scanner.scan_text(text, validate)

def scan_file_for_pii(filepath, encoding='utf-8'):
    return scanner.scan_file(filepath, encoding)

def scan_directory_for_pii(directory_path, recursive=True, file_extensions=None):
    return scanner.scan_directory(directory_path, recursive, file_extensions)

def generate_pii_report(scan_results, output_format='json'):
    return scanner.generate_report(scan_results, output_format)

def save_pii_results(results, output_file, format='json'):
    return scanner.save_results(results, output_file, format)

def validate_ssn_number(ssn):
    return scanner.validate_ssn(ssn)

def validate_credit_card_number(number):
    return scanner.validate_credit_card(number)

def validate_aadhar_number(aadhar):
    return scanner.validate_aadhar(aadhar)

def validate_indian_phone_number(phone):
    return scanner.validate_indian_phone(phone)

scan_text_function = types.FunctionDeclaration(
    name="scan_text_for_pii",
    description="Scan text content for personally identifiable information (PII) including SSN, credit cards, emails, phone numbers, etc.",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "text": types.Schema(
                type=types.Type.STRING,
                description="Text content to scan for PII"
            ),
            "validate": types.Schema(
                type=types.Type.BOOLEAN,
                description="Whether to validate found PII using algorithm checks (default: True)"
            )
        },
        required=["text"]
    )
)

scan_file_function = types.FunctionDeclaration(
    name="scan_file_for_pii",
    description="Scan a file for PII content with detailed analysis and statistics",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "filepath": types.Schema(
                type=types.Type.STRING,
                description="Path to the file to scan for PII"
            ),
            "encoding": types.Schema(
                type=types.Type.STRING,
                description="File encoding (default: utf-8)"
            )
        },
        required=["filepath"]
    )
)

scan_directory_function = types.FunctionDeclaration(
    name="scan_directory_for_pii",
    description="Scan an entire directory for PII across multiple files",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "directory_path": types.Schema(
                type=types.Type.STRING,
                description="Path to the directory to scan"
            ),
            "recursive": types.Schema(
                type=types.Type.BOOLEAN,
                description="Whether to scan subdirectories recursively (default: True)"
            ),
            "file_extensions": types.Schema(
                type=types.Type.ARRAY,
                items=types.Schema(type=types.Type.STRING),
                description="List of file extensions to scan (default: common text file types)"
            )
        },
        required=["directory_path"]
    )
)

generate_report_function = types.FunctionDeclaration(
    name="generate_pii_report",
    description="Generate a formatted report from PII scan results",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "scan_results": types.Schema(
                type=types.Type.OBJECT,
                description="Scan results dictionary from previous PII scan"
            ),
            "output_format": types.Schema(
                type=types.Type.STRING,
                description="Report format: 'json' or 'summary' (default: json)"
            )
        },
        required=["scan_results"]
    )
)

save_results_function = types.FunctionDeclaration(
    name="save_pii_results",
    description="Save PII scan results to a file",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "results": types.Schema(
                type=types.Type.OBJECT,
                description="Scan results to save"
            ),
            "output_file": types.Schema(
                type=types.Type.STRING,
                description="Path where to save the results file"
            ),
            "format": types.Schema(
                type=types.Type.STRING,
                description="Output format: 'json' or 'summary' (default: json)"
            )
        },
        required=["results", "output_file"]
    )
)

validate_ssn_function = types.FunctionDeclaration(
    name="validate_ssn_number",
    description="Validate if a Social Security Number is properly formatted and not in known invalid patterns",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "ssn": types.Schema(
                type=types.Type.STRING,
                description="Social Security Number to validate"
            )
        },
        required=["ssn"]
    )
)

validate_credit_card_function = types.FunctionDeclaration(
    name="validate_credit_card_number",
    description="Validate credit card number using Luhn algorithm",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "number": types.Schema(
                type=types.Type.STRING,
                description="Credit card number to validate"
            )
        },
        required=["number"]
    )
)

validate_aadhar_function = types.FunctionDeclaration(
    name="validate_aadhar_number",
    description="Validate Indian Aadhar number format and basic checks",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "aadhar": types.Schema(
                type=types.Type.STRING,
                description="Aadhar number to validate"
            )
        },
        required=["aadhar"]
    )
)

validate_phone_function = types.FunctionDeclaration(
    name="validate_indian_phone_number",
    description="Validate Indian phone number format and basic checks",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "phone": types.Schema(
                type=types.Type.STRING,
                description="Indian phone number to validate"
            )
        },
        required=["phone"]
    )
)