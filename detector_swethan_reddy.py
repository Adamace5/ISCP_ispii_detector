#!/usr/bin/env python3


import csv
import json
import re
import sys
from typing import Dict, List, Tuple, Any
import argparse

class PIIDetector:
    """
    Advanced PII Detection and Redaction System
    
    Implements both standalone and combinatorial PII detection with
    high accuracy and minimal false positives.
    """
    
    def __init__(self):
        # Regex patterns for standalone PII
        self.patterns = {
            'phone': re.compile(r'\b\d{10}\b'),
            'aadhar': re.compile(r'\b\d{4}\s*\d{4}\s*\d{4}\b|\b\d{12}\b'),
            'passport': re.compile(r'\b[A-Z]\d{7}\b'),
            'upi_id': re.compile(r'\b[\w\.-]+@[\w\.-]+\b|^\d{10}@[a-zA-Z]+$'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'ip_address': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
        }
        
        # Address pattern (more comprehensive)
        self.address_pattern = re.compile(
            r'.*(?:street|road|avenue|lane|drive|place|court|way|circle|'
            r'block|flat|apartment|house|building).*\d{6}.*',
            re.IGNORECASE
        )
        
        # Name pattern (first + last name)
        self.full_name_pattern = re.compile(r'^[A-Za-z]+\s+[A-Za-z]+.*$')
        
        # Combinatorial PII fields
        self.combinatorial_fields = {
            'name', 'first_name', 'last_name', 'email', 'address', 
            'city', 'pin_code', 'device_id', 'ip_address'
        }
        
        # Fields that are definitely not PII
        self.non_pii_fields = {
            'customer_id', 'order_value', 'product', 'category', 'transaction_type',
            'product_id', 'product_category', 'amount', 'order_id', 'booking_reference',
            'app_version', 'transaction_id', 'status', 'order_date', 'state',
            'product_name', 'age', 'verification_status', 'query_type', 'merchant',
            'product_description', 'price', 'sms_consent', 'username', 'last_login',
            'kyc_status', 'region', 'warehouse_code', 'carrier', 'subscription_type',
            'renewal_date', 'brand', 'model', 'size', 'currency', 'exchange_rate',
            'notification_preference', 'product_rating', 'review_count', 'family_size',
            'delivery_zone', 'app_name', 'version', 'issue_date', 'profession',
            'address_proof', 'ticket_id', 'search_query', 'filters', 'auto_debit',
            'state_code', 'gst_number', 'feature_flag', 'enabled', 'discount_code',
            'validity', 'nationality', 'wishlist_count', 'biometric_status',
            'payment_gateway', 'transaction_fee', 'travel_insurance', 'coverage',
            'military_service', 'ncc_certificate', 'conference_call', 'participants_limit',
            'jewelry_insurance', 'premium', 'diplomatic_immunity', 'official_travel',
            'property_registration', 'stamp_duty', 'music_streaming', 'offline_downloads',
            'concert_tickets', 'artist_alerts', 'artist_visa', 'multi_entry',
            'performance_permit', 'comedy_club', 'performance_rights'
        }

    def is_standalone_pii(self, field: str, value: str) -> bool:
        """Check if a field-value pair is standalone PII"""
        if not value or not isinstance(value, str):
            return False
            
        value = str(value).strip()
        
        # Phone number (10 digits)
        if field == 'phone' and self.patterns['phone'].match(value):
            return True
            
        # Aadhar card (12 digits)
        if field == 'aadhar' and self.patterns['aadhar'].match(value.replace(' ', '')):
            return True
            
        # Passport number
        if field == 'passport' and self.patterns['passport'].match(value):
            return True
            
        # UPI ID
        if field == 'upi_id':
            # Username-based UPI (user@upi)
            if '@' in value and self.patterns['email'].match(value):
                return True
            # Number-based UPI (9876543210@ybl)
            if value.count('@') == 1:
                phone_part = value.split('@')[0]
                if self.patterns['phone'].match(phone_part):
                    return True
                    
        return False

    def detect_combinatorial_pii(self, data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Detect combinatorial PII (requires 2+ different types from combinatorial list)
        Returns (is_pii, list_of_pii_fields)
        """
        pii_types = set()
        pii_fields = []
        
        for field, value in data.items():
            if not value or field in self.non_pii_fields:
                continue
                
            value = str(value).strip()
            
            # Full name (counts as one type)
            if field == 'name' and self.full_name_pattern.match(value):
                pii_types.add('name')
                pii_fields.append(field)
                
            # First name + Last name (together count as one type)
            elif field in ['first_name', 'last_name']:
                if 'first_name' in data and 'last_name' in data:
                    if data.get('first_name') and data.get('last_name'):
                        pii_types.add('name')
                        pii_fields.append(field)
                
            # Email address (one type)
            elif field == 'email' and self.patterns['email'].match(value):
                pii_types.add('email')
                pii_fields.append(field)
                
            # Physical address (one type)
            elif field == 'address' and len(value) > 10:
                # Enhanced address detection
                address_indicators = ['street', 'road', 'avenue', 'flat', 'house', 'building', 'mg road', 'block']
                has_address_indicator = any(indicator in value.lower() for indicator in address_indicators)
                has_pincode = bool(re.search(r'\b\d{6}\b', value))
                
                if has_address_indicator or has_pincode:
                    pii_types.add('address')
                    pii_fields.append(field)
                    
            # City + Pin code (together count as one type but need both present)
            elif field in ['city', 'pin_code']:
                if 'city' in data and 'pin_code' in data:
                    city_val = data.get('city')
                    pin_val = data.get('pin_code')
                    if city_val and pin_val and str(city_val).strip() and str(pin_val).strip():
                        pii_types.add('location')
                        pii_fields.extend(['city', 'pin_code'])
                        
            # Device ID / IP Address (only with user context, one type)
            elif field in ['device_id', 'ip_address']:
                user_context_fields = ['name', 'email', 'phone', 'first_name', 'last_name']
                has_user_context = any(data.get(uf) for uf in user_context_fields)
                if has_user_context:
                    pii_types.add('device_info')
                    pii_fields.append(field)
        
        # Remove duplicates from pii_fields
        pii_fields = list(set(pii_fields))
        
        # Special case: if we only have city+pin_code, that's still valid combinatorial PII
        if len(pii_types) == 1 and 'location' in pii_types:
            # city + pin_code together are considered combinatorial PII
            return True, pii_fields
            
        # Need at least 2 different types of combinatorial PII
        return len(pii_types) >= 2, pii_fields

    def redact_value(self, field: str, value: str) -> str:
        """Apply appropriate redaction based on field type and value"""
        if not value:
            return value
            
        value = str(value).strip()
        
        # Phone number redaction (show first 2 and last 2 digits)
        if field == 'phone' and self.patterns['phone'].match(value):
            return f"{value[:2]}XXXXXX{value[-2:]}"
            
        # Aadhar redaction
        if field == 'aadhar':
            clean_aadhar = value.replace(' ', '')
            if self.patterns['aadhar'].match(clean_aadhar):
                return f"{clean_aadhar[:4]}XXXX{clean_aadhar[-4:]}"
                
        # Passport redaction
        if field == 'passport' and self.patterns['passport'].match(value):
            return f"{value[0]}XXXXXX{value[-1]}"
            
        # UPI ID redaction
        if field == 'upi_id' and '@' in value:
            parts = value.split('@')
            username = parts[0]
            domain = parts[1]
            if len(username) > 4:
                return f"{username[:2]}XXXX{username[-2:]}@{domain}"
            else:
                return f"XXX@{domain}"
                
        # Email redaction
        if field == 'email' and self.patterns['email'].match(value):
            local, domain = value.split('@', 1)
            if len(local) > 3:
                return f"{local[:2]}XXX@{domain}"
            else:
                return f"XXX@{domain}"
                
        # Name redaction
        if field in ['name', 'first_name', 'last_name']:
            words = value.split()
            if field == 'name' and len(words) >= 2:
                # For full names, redact first and last name separately
                return f"{words[0][0]}XXX {words[-1][0]}XXX"
            elif len(value) > 1:
                return f"{value[0]}XXX"
            return "XXX"
            
        # Address redaction
        if field == 'address':
            return "[REDACTED_ADDRESS]"
            
        # Default redaction for other PII
        if field in ['city', 'pin_code']:
            if len(value) > 2:
                return f"{value[0]}XXX"
            else:
                return "XXX"
                
        if field in ['device_id', 'ip_address']:
            if len(value) > 4:
                return f"{value[:2]}XXX{value[-2:]}"
            else:
                return "XXX"
                
        # Generic fallback
        if len(value) > 4:
            return f"{value[:2]}XXX{value[-2:]}"
        else:
            return "XXX"

    def process_record(self, data: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
        """
        Process a single record and return redacted data with PII flag
        """
        redacted_data = data.copy()
        is_pii = False
        
        # Check for standalone PII
        for field, value in data.items():
            if self.is_standalone_pii(field, value):
                redacted_data[field] = self.redact_value(field, str(value))
                is_pii = True
                
        # Check for combinatorial PII
        has_combinatorial_pii, pii_fields = self.detect_combinatorial_pii(data)
        if has_combinatorial_pii:
            is_pii = True
            for field in pii_fields:
                if field in redacted_data:
                    # Don't double-redact standalone PII fields
                    if not any(self.is_standalone_pii(f, data.get(f)) for f in [field]):
                        redacted_data[field] = self.redact_value(field, str(data[field]))
                    
        return redacted_data, is_pii

def main():
    parser = argparse.ArgumentParser(description='PII Detection and Redaction System')
    parser.add_argument('input_file', help='Input CSV file path')
    parser.add_argument('--output', '-o', help='Output CSV file path', 
                       default='redacted_output.csv')
    
    args = parser.parse_args()
    
    detector = PIIDetector()
    
    try:
        with open(args.input_file, 'r', encoding='utf-8') as infile:
            reader = csv.DictReader(infile)
            
            # Prepare output file
            output_file = args.output
            with open(output_file, 'w', encoding='utf-8', newline='') as outfile:
                fieldnames = ['record_id', 'redacted_data_json', 'is_pii']
                writer = csv.DictWriter(outfile, fieldnames=fieldnames)
                writer.writeheader()
                
                processed_count = 0
                pii_count = 0
                
                for row in reader:
                    record_id = row.get('record_id', '')
                    data_json = row.get('data_json', '{}')
                    
                    try:
                        # Parse JSON data
                        data = json.loads(data_json)
                        
                        # Process the record
                        redacted_data, is_pii_detected = detector.process_record(data)
                        
                        # Write result
                        writer.writerow({
                            'record_id': record_id,
                            'redacted_data_json': json.dumps(redacted_data, separators=(',', ':')),
                            'is_pii': is_pii_detected
                        })
                        
                        processed_count += 1
                        if is_pii_detected:
                            pii_count += 1
                            
                    except json.JSONDecodeError as e:
                        print(f"Error parsing JSON for record {record_id}: {e}")
                        # Write original data with False flag for invalid JSON
                        writer.writerow({
                            'record_id': record_id,
                            'redacted_data_json': data_json,
                            'is_pii': False
                        })
                        processed_count += 1
                
                print(f"Processing complete!")
                print(f"Total records processed: {processed_count}")
                print(f"Records with PII detected: {pii_count}")
                print(f"Output saved to: {output_file}")
                
    except FileNotFoundError:
        print(f"Error: Input file '{args.input_file}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
