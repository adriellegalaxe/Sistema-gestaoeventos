#!/usr/bin/env python3
"""
Comprehensive Backend API Testing for ISEPAM Event Management System
Tests all endpoints including authentication, events, sessions, QR codes, attendance, and certificates
"""

import requests
import sys
import json
from datetime import datetime, timedelta
import uuid

class ISEPAMAPITester:
    def __init__(self, base_url="https://isepam-eventos.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.tokens = {}  # Store tokens for different user types
        self.users = {}   # Store user data
        self.events = {}  # Store created events
        self.sessions = {} # Store created sessions
        self.tests_run = 0
        self.tests_passed = 0
        self.failed_tests = []

    def log_test(self, name, success, details=""):
        """Log test results"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            print(f"✅ {name}")
        else:
            self.failed_tests.append({"name": name, "details": details})
            print(f"❌ {name} - {details}")

    def make_request(self, method, endpoint, data=None, token=None, expect_status=200):
        """Make HTTP request with proper headers"""
        url = f"{self.api_url}/{endpoint}"
        headers = {'Content-Type': 'application/json'}
        
        if token:
            headers['Authorization'] = f'Bearer {token}'
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers)
            elif method == 'PUT':
                response = requests.put(url, json=data, headers=headers)
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers)
            
            success = response.status_code == expect_status
            return success, response
            
        except Exception as e:
            return False, str(e)

    def test_user_registration(self):
        """Test user registration with different user types"""
        print("\n🔍 Testing User Registration...")
        
        # Test data for different user types
        test_users = [
            {
                "user_type": "aluno",
                "enrollment_number": "2024001",
                "full_name": "João Silva Santos",
                "cpf": "11144477735",  # Valid CPF
                "email": f"joao.silva.{uuid.uuid4().hex[:8]}@test.com",
                "password": "senha123"
            },
            {
                "user_type": "professor", 
                "enrollment_number": "PROF001",
                "full_name": "Maria Oliveira",
                "cpf": "12345678901",  # Invalid CPF for testing
                "email": f"maria.prof.{uuid.uuid4().hex[:8]}@test.com",
                "password": "senha123"
            },
            {
                "user_type": "coordenador",
                "enrollment_number": "COORD001", 
                "full_name": "Carlos Coordenador",
                "cpf": "11144477735",  # Valid CPF
                "email": f"carlos.coord.{uuid.uuid4().hex[:8]}@test.com",
                "password": "senha123"
            }
        ]
        
        for user_data in test_users:
            success, response = self.make_request('POST', 'auth/register', user_data, expect_status=200)
            
            if success:
                result = response.json()
                self.users[user_data['user_type']] = user_data
                self.log_test(f"Register {user_data['user_type']}", True)
                
                # Check CPF validation
                if user_data['cpf'] == "11144477735":
                    cpf_valid = result.get('cpf_valid', False)
                    self.log_test(f"CPF validation for {user_data['user_type']}", cpf_valid)
                else:
                    cpf_invalid = not result.get('cpf_valid', True)
                    self.log_test(f"CPF invalid detection for {user_data['user_type']}", cpf_invalid)
            else:
                self.log_test(f"Register {user_data['user_type']}", False, 
                            f"Status: {response.status_code if hasattr(response, 'status_code') else 'Error'}")

    def test_user_login(self):
        """Test user login for all registered users"""
        print("\n🔍 Testing User Login...")
        
        for user_type, user_data in self.users.items():
            login_data = {
                "email": user_data['email'],
                "password": user_data['password']
            }
            
            success, response = self.make_request('POST', 'auth/login', login_data, expect_status=200)
            
            if success:
                result = response.json()
                self.tokens[user_type] = result['access_token']
                self.log_test(f"Login {user_type}", True)
                
                # Verify user data in response
                user_info = result.get('user', {})
                name_match = user_info.get('full_name') == user_data['full_name']
                email_match = user_info.get('email') == user_data['email']
                type_match = user_info.get('user_type') == user_data['user_type']
                
                self.log_test(f"Login data validation {user_type}", 
                            name_match and email_match and type_match)
            else:
                self.log_test(f"Login {user_type}", False,
                            f"Status: {response.status_code if hasattr(response, 'status_code') else 'Error'}")

    def test_auth_me(self):
        """Test /auth/me endpoint for authenticated users"""
        print("\n🔍 Testing Auth Me Endpoint...")
        
        for user_type, token in self.tokens.items():
            success, response = self.make_request('GET', 'auth/me', token=token, expect_status=200)
            
            if success:
                user_info = response.json()
                expected_user = self.users[user_type]
                
                # Verify returned user data
                name_match = user_info.get('full_name') == expected_user['full_name']
                email_match = user_info.get('email') == expected_user['email']
                type_match = user_info.get('user_type') == expected_user['user_type']
                
                self.log_test(f"Auth me {user_type}", name_match and email_match and type_match)
            else:
                self.log_test(f"Auth me {user_type}", False,
                            f"Status: {response.status_code if hasattr(response, 'status_code') else 'Error'}")

    def test_event_creation(self):
        """Test event creation (coordinators only)"""
        print("\n🔍 Testing Event Creation...")
        
        # Test with coordinator token
        if 'coordenador' in self.tokens:
            event_data = {
                "name": "Workshop de Programação Python",
                "target_courses": ["informatica"],
                "manual_hours": 4.0,
                "description": "Workshop prático de Python para iniciantes",
                "event_date": "2024-12-15"
            }
            
            success, response = self.make_request('POST', 'events', event_data, 
                                                token=self.tokens['coordenador'], expect_status=200)
            
            if success:
                event = response.json()
                self.events['python_workshop'] = event
                self.log_test("Create event (coordinator)", True)
                
                # Verify event data
                name_match = event.get('name') == event_data['name']
                courses_match = event.get('target_courses') == event_data['target_courses']
                hours_match = event.get('manual_hours') == event_data['manual_hours']
                
                self.log_test("Event data validation", name_match and courses_match and hours_match)
            else:
                self.log_test("Create event (coordinator)", False,
                            f"Status: {response.status_code if hasattr(response, 'status_code') else 'Error'}")
        
        # Test with non-coordinator (should fail)
        if 'aluno' in self.tokens:
            event_data = {
                "name": "Evento Não Autorizado",
                "target_courses": ["pedagogia"],
                "event_date": "2024-12-20"
            }
            
            success, response = self.make_request('POST', 'events', event_data,
                                                token=self.tokens['aluno'], expect_status=403)
            
            self.log_test("Create event (non-coordinator blocked)", success)

    def test_event_operations(self):
        """Test event CRUD operations"""
        print("\n🔍 Testing Event Operations...")
        
        # Test get all events
        success, response = self.make_request('GET', 'events', expect_status=200)
        if success:
            events = response.json()
            self.log_test("Get all events", isinstance(events, list))
        else:
            self.log_test("Get all events", False)
        
        # Test get specific event
        if 'python_workshop' in self.events:
            event_id = self.events['python_workshop']['id']
            success, response = self.make_request('GET', f'events/{event_id}', expect_status=200)
            
            if success:
                event = response.json()
                self.log_test("Get specific event", event.get('id') == event_id)
            else:
                self.log_test("Get specific event", False)
            
            # Test update event (coordinator only)
            if 'coordenador' in self.tokens:
                update_data = {
                    "name": "Workshop Avançado de Python",
                    "target_courses": ["informatica", "pedagogia"],
                    "manual_hours": 6.0,
                    "description": "Workshop avançado com foco em aplicações práticas",
                    "event_date": "2024-12-15"
                }
                
                success, response = self.make_request('PUT', f'events/{event_id}', update_data,
                                                    token=self.tokens['coordenador'], expect_status=200)
                
                if success:
                    updated_event = response.json()
                    self.events['python_workshop'] = updated_event
                    self.log_test("Update event", updated_event.get('name') == update_data['name'])
                else:
                    self.log_test("Update event", False)

    def test_session_operations(self):
        """Test session creation and management"""
        print("\n🔍 Testing Session Operations...")
        
        if 'python_workshop' in self.events and 'coordenador' in self.tokens:
            event_id = self.events['python_workshop']['id']
            
            # Create session
            session_data = {
                "event_id": event_id,
                "title": "Introdução ao Python",
                "speakers": "Dr. João Python",
                "start_time": "09:00",
                "end_time": "12:00",
                "description": "Conceitos básicos de Python",
                "target_courses": ["informatica"]
            }
            
            success, response = self.make_request('POST', 'sessions', session_data,
                                                token=self.tokens['coordenador'], expect_status=200)
            
            if success:
                session = response.json()
                self.sessions['intro_python'] = session
                self.log_test("Create session", True)
                
                # Verify session data
                title_match = session.get('title') == session_data['title']
                event_match = session.get('event_id') == event_id
                
                self.log_test("Session data validation", title_match and event_match)
            else:
                self.log_test("Create session", False)
            
            # Get event sessions
            success, response = self.make_request('GET', f'events/{event_id}/sessions', expect_status=200)
            
            if success:
                sessions = response.json()
                self.log_test("Get event sessions", isinstance(sessions, list) and len(sessions) > 0)
            else:
                self.log_test("Get event sessions", False)

    def test_qr_code_generation(self):
        """Test QR code generation for events"""
        print("\n🔍 Testing QR Code Generation...")
        
        if 'python_workshop' in self.events:
            event_id = self.events['python_workshop']['id']
            
            # Test QR code generation
            url = f"{self.api_url}/events/{event_id}/qrcode"
            try:
                response = requests.get(url)
                success = response.status_code == 200 and response.headers.get('content-type') == 'image/png'
                self.log_test("Generate QR code", success)
            except Exception as e:
                self.log_test("Generate QR code", False, str(e))

    def test_attendance_confirmation(self):
        """Test attendance confirmation via QR token"""
        print("\n🔍 Testing Attendance Confirmation...")
        
        if 'python_workshop' in self.events and 'aluno' in self.tokens:
            event = self.events['python_workshop']
            qr_token = event.get('qr_code_token')
            
            if qr_token:
                attendance_data = {"qr_token": qr_token}
                
                success, response = self.make_request('POST', 'attendance/confirm', attendance_data,
                                                    token=self.tokens['aluno'], expect_status=200)
                
                if success:
                    result = response.json()
                    self.log_test("Confirm attendance", True)
                    
                    # Check if certificate was generated
                    cert_id = result.get('certificate_id')
                    self.log_test("Certificate auto-generation", cert_id is not None)
                else:
                    self.log_test("Confirm attendance", False)
                
                # Test duplicate attendance (should handle gracefully)
                success, response = self.make_request('POST', 'attendance/confirm', attendance_data,
                                                    token=self.tokens['aluno'], expect_status=200)
                
                if success:
                    result = response.json()
                    duplicate_handled = "já confirmada" in result.get('message', '').lower()
                    self.log_test("Duplicate attendance handling", duplicate_handled)
                else:
                    self.log_test("Duplicate attendance handling", False)

    def test_certificates(self):
        """Test certificate operations"""
        print("\n🔍 Testing Certificate Operations...")
        
        if 'aluno' in self.tokens:
            # Get user certificates
            success, response = self.make_request('GET', 'certificates', token=self.tokens['aluno'], expect_status=200)
            
            if success:
                certificates = response.json()
                self.log_test("Get user certificates", isinstance(certificates, list))
                
                # Test certificate download if any exist
                if certificates:
                    cert_id = certificates[0]['id']
                    
                    # Test PDF download
                    url = f"{self.api_url}/certificates/{cert_id}/download"
                    headers = {'Authorization': f'Bearer {self.tokens["aluno"]}'}
                    
                    try:
                        response = requests.get(url, headers=headers)
                        success = (response.status_code == 200 and 
                                 response.headers.get('content-type') == 'application/pdf')
                        self.log_test("Download certificate PDF", success)
                    except Exception as e:
                        self.log_test("Download certificate PDF", False, str(e))
            else:
                self.log_test("Get user certificates", False)

    def test_home_stats(self):
        """Test home page statistics"""
        print("\n🔍 Testing Home Statistics...")
        
        success, response = self.make_request('GET', 'home/stats', expect_status=200)
        
        if success:
            stats = response.json()
            has_recent = 'recent_completed' in stats
            has_open = 'open_events' in stats
            
            self.log_test("Home stats structure", has_recent and has_open)
            
            # Verify data types
            recent_is_list = isinstance(stats.get('recent_completed', []), list)
            open_is_list = isinstance(stats.get('open_events', []), list)
            
            self.log_test("Home stats data types", recent_is_list and open_is_list)
        else:
            self.log_test("Home stats", False)

    def test_authorization_controls(self):
        """Test authorization controls for protected endpoints"""
        print("\n🔍 Testing Authorization Controls...")
        
        # Test unauthorized access (no token)
        success, response = self.make_request('GET', 'auth/me', expect_status=401)
        self.log_test("Unauthorized access blocked", success)
        
        # Test invalid token
        success, response = self.make_request('GET', 'auth/me', token="invalid_token", expect_status=401)
        self.log_test("Invalid token rejected", success)
        
        # Test coordinator-only endpoints with non-coordinator
        if 'aluno' in self.tokens:
            event_data = {
                "name": "Unauthorized Event",
                "target_courses": ["informatica"],
                "event_date": "2024-12-25"
            }
            
            success, response = self.make_request('POST', 'events', event_data,
                                                token=self.tokens['aluno'], expect_status=403)
            self.log_test("Non-coordinator event creation blocked", success)

    def cleanup_test_data(self):
        """Clean up test data"""
        print("\n🧹 Cleaning up test data...")
        
        # Delete created sessions
        if 'intro_python' in self.sessions and 'coordenador' in self.tokens:
            session_id = self.sessions['intro_python']['id']
            success, response = self.make_request('DELETE', f'sessions/{session_id}',
                                                token=self.tokens['coordenador'], expect_status=200)
            self.log_test("Delete session", success)
        
        # Delete created events
        if 'python_workshop' in self.events and 'coordenador' in self.tokens:
            event_id = self.events['python_workshop']['id']
            success, response = self.make_request('DELETE', f'events/{event_id}',
                                                token=self.tokens['coordenador'], expect_status=200)
            self.log_test("Delete event", success)

    def run_all_tests(self):
        """Run complete test suite"""
        print("🚀 Starting ISEPAM Backend API Tests")
        print(f"📍 Testing against: {self.base_url}")
        print("=" * 60)
        
        try:
            # Core functionality tests
            self.test_user_registration()
            self.test_user_login()
            self.test_auth_me()
            
            # Event management tests
            self.test_event_creation()
            self.test_event_operations()
            self.test_session_operations()
            
            # QR and attendance tests
            self.test_qr_code_generation()
            self.test_attendance_confirmation()
            
            # Certificate tests
            self.test_certificates()
            
            # Home page tests
            self.test_home_stats()
            
            # Security tests
            self.test_authorization_controls()
            
            # Cleanup
            self.cleanup_test_data()
            
        except Exception as e:
            print(f"\n💥 Test suite crashed: {str(e)}")
            return False
        
        # Print results
        print("\n" + "=" * 60)
        print("📊 TEST RESULTS")
        print("=" * 60)
        print(f"✅ Tests Passed: {self.tests_passed}")
        print(f"❌ Tests Failed: {len(self.failed_tests)}")
        print(f"📈 Success Rate: {(self.tests_passed/self.tests_run)*100:.1f}%")
        
        if self.failed_tests:
            print("\n❌ FAILED TESTS:")
            for test in self.failed_tests:
                print(f"  • {test['name']}: {test['details']}")
        
        return len(self.failed_tests) == 0

def main():
    """Main test execution"""
    tester = ISEPAMAPITester()
    success = tester.run_all_tests()
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())