#!/usr/bin/env python3


import csv
import json
import re
import sys
from typing import Dict, List, Tuple, Any
import argparse

class PIIDetector:
    
    
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
        
        # Address pattern 
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
        Detect combinatorial PII (requires 2+ fields from combinatorial list)
        Returns (is_pii, list_of_pii_fields)
        """
        pii_fields = []
        
        for field, value in data.items():
            if not value or field in self.non_pii_fields:
                continue
                
            value = str(value).strip()
            
            # Name detection (full name with first + last)
            if field == 'name' and self.full_name_pattern.match(value):
                pii_fields.append(field)
                
            # First name (only if last_name also exists)
            elif field == 'first_name' and 'last_name' in data and data.get('last_name'):
                pii_fields.append(field)
                
            # Last name (only if first_name also exists)  
            elif field == 'last_name' and 'first_name' in data and data.get('first_name'):
                pii_fields.append(field)
                
            # Email address
            elif field == 'email' and self.patterns['email'].match(value):
                pii_fields.append(field)
                
            # Physical address (comprehensive check)
            elif field == 'address' and len(value) > 10:
                # Look for street indicators + pin code pattern
                if self.address_pattern.search(value) or any(
                    keyword in value.lower() 
                    for keyword in ['street', 'road', 'avenue', 'flat', 'house', 'building', 'mg road']
                ):
                    pii_fields.append(field)
                    
            # City (only if pin_code also exists)
            elif field == 'city' and 'pin_code' in data and data.get('pin_code'):
                pii_fields.append(field)
                
            # Pin code (only if city also exists)
            elif field == 'pin_code' and 'city' in data and data.get('city'):
                pii_fields.append(field)
                        
            # Device ID / IP Address (only when tied to user context)
            elif field in ['device_id', 'ip_address']:
                # Check if there's user context (name, email, or phone)
                user_context_fields = ['name', 'email', 'phone', 'first_name', 'last_name']
                has_user_context = any(
                    data.get(uf) for uf in user_context_fields
                )
                if has_user_context:
                    pii_fields.append(field)
        
        # Remove duplicates
        unique_pii_fields = list(set(pii_fields))
        
        # Count combinations properly
        combinatorial_count = 0
        
        # Full name counts as 1
        if 'name' in unique_pii_fields:
            combinatorial_count += 1
            
        # First name + last name together count as 1
        if 'first_name' in unique_pii_fields and 'last_name' in unique_pii_fields:
            combinatorial_count += 1
            
        # Email counts as 1
        if 'email' in unique_pii_fields:
            combinatorial_count += 1
            
        # Address counts as 1
        if 'address' in unique_pii_fields:
            combinatorial_count += 1
            
        # City + pin_code together count as 1
        if 'city' in unique_pii_fields and 'pin_code' in unique_pii_fields:
            combinatorial_count += 1
            
        # Device/IP with user context counts as 1
        if any(field in unique_pii_fields for field in ['device_id', 'ip_address']):
            combinatorial_count += 1
            
        return combinatorial_count >= 2, unique_pii_fields

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
            if len(parts[0]) > 4:
                return f"{parts[0][:2]}XXX{parts[0][-2:]}@{parts[1]}"
            else:
                return f"XXX@{parts[1]}"
                
        # Email redaction
        if field == 'email' and self.patterns['email'].match(value):
            local, domain = value.split('@')
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
