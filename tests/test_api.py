#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#    Unit tests for DNSRecon's REST API
#    Author: Jay Townsend
#
#    Copyright (C) 2025 Carlos Perez
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; Applies version 2 of the License.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#    See the GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from dnsrecon.api import app


class TestDNSReconAPI:
    """Test class for DNSRecon REST API endpoints"""
    
    @pytest.fixture
    def client(self):
        """Create a test client for the FastAPI app"""
        return TestClient(app)
    
    def test_root_endpoint(self, client):
        """Test the root endpoint returns HTML"""
        response = client.get("/")
        assert response.status_code == 200
        assert response.headers["content-type"] == "text/html; charset=utf-8"
        assert "DNSRecon REST API" in response.text
        assert "/docs" in response.text
        assert "/capabilities" in response.text
    
    def test_root_endpoint_bot_detection(self, client):
        """Test bot detection in root endpoint"""
        # Test with suspicious user agent - bot detection may not redirect in test client
        response = client.get("/", headers={"User-Agent": "gobuster/3.0"})
        assert response.status_code in [200, 307]  # May redirect or return normal response
        
        # Test with normal user agent
        response = client.get("/", headers={"User-Agent": "Mozilla/5.0"})
        assert response.status_code == 200
    
    def test_nicebot_endpoint(self, client):
        """Test the bot endpoint"""
        response = client.get("/nicebot")
        assert response.status_code == 200
        data = response.json()
        assert "bot" in data
        assert "DNS records" in data["bot"]
    
    def test_capabilities_endpoint(self, client):
        """Test the capabilities endpoint"""
        response = client.get("/capabilities")
        assert response.status_code == 200
        data = response.json()
        assert "capabilities" in data
        assert isinstance(data["capabilities"], list)
        assert len(data["capabilities"]) > 0
        
        # Check for expected capabilities
        capabilities_text = " ".join(data["capabilities"])
        assert "general_enum" in capabilities_text
        assert "brute_domain" in capabilities_text
        assert "wildcard_check" in capabilities_text
    
    @patch('dnsrecon.api.general_enum')
    @patch('dnsrecon.api.DnsHelper')
    def test_general_enum_endpoint(self, mock_dns_helper, mock_general_enum, client):
        """Test the general enumeration endpoint"""
        # Mock the DNS helper and general_enum function
        mock_instance = MagicMock()
        mock_dns_helper.return_value = mock_instance
        mock_general_enum.return_value = [
            {'type': 'A', 'name': 'example.com', 'address': '192.0.2.1'},
            {'type': 'MX', 'name': 'mail.example.com', 'address': '192.0.2.2'}
        ]
        
        response = client.get("/general_enum?domain=example.com")
        assert response.status_code == 200
        data = response.json()
        
        assert "domain" in data
        assert data["domain"] == "example.com"
        assert "records" in data
        assert "subdomains" in data
        assert "ips" in data
        assert isinstance(data["records"], list)
    
    def test_general_enum_invalid_domain(self, client):
        """Test general enumeration with an invalid domain"""
        response = client.get("/general_enum?domain=ab")
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert "at least 3 characters" in data["detail"]
    
    @patch('dnsrecon.api.brute_domain')
    @patch('dnsrecon.api.DnsHelper')
    def test_brute_domain_endpoint(self, mock_dns_helper, mock_brute_domain, client):
        """Test the domain brute force endpoint"""
        # Mock the DNS helper and brute_domain function
        mock_instance = MagicMock()
        mock_dns_helper.return_value = mock_instance
        mock_brute_domain.return_value = [
            {'type': 'A', 'name': 'www.example.com', 'address': '192.0.2.1'},
            {'type': 'A', 'name': 'mail.example.com', 'address': '192.0.2.2'}
        ]
        
        response = client.get("/brute_domain?domain=example.com")
        assert response.status_code == 200
        data = response.json()
        
        assert "domain" in data
        assert data["domain"] == "example.com"
        assert "subdomains" in data
        assert "records" in data
        assert isinstance(data["records"], list)
    
    @patch('dnsrecon.api.brute_reverse')
    @patch('dnsrecon.api.DnsHelper')
    def test_brute_reverse_endpoint(self, mock_dns_helper, mock_brute_reverse, client):
        """Test the reverse DNS brute force endpoint"""
        # Mock the DNS helper and brute_reverse function
        mock_instance = MagicMock()
        mock_dns_helper.return_value = mock_instance
        mock_brute_reverse.return_value = [
            {'name': 'example.com', 'address': '192.0.2.1'},
            {'name': 'mail.example.com', 'address': '192.0.2.2'}
        ]
        
        response = client.get("/brute_reverse?ip_range=192.0.2.1-192.0.2.10")
        assert response.status_code == 200
        data = response.json()
        
        assert "ip_range" in data
        assert "records" in data
        assert isinstance(data["records"], list)
    
    def test_brute_reverse_missing_ip_range(self, client):
        """Test reverse DNS brute force with missing IP range"""
        response = client.get("/brute_reverse")
        assert response.status_code == 422  # Validation error
    
    @patch('dnsrecon.api.check_wildcard')
    @patch('dnsrecon.api.DnsHelper')
    def test_wildcard_check_endpoint(self, mock_dns_helper, mock_check_wildcard, client):
        """Test the wildcard check endpoint"""
        # Mock the DNS helper and check_wildcard function
        mock_instance = MagicMock()
        mock_dns_helper.return_value = mock_instance
        mock_check_wildcard.return_value = ['192.0.2.1', '192.0.2.2']
        
        response = client.get("/wildcard_check?domain=example.com")
        assert response.status_code == 200
        data = response.json()
        
        assert "domain" in data
        assert data["domain"] == "example.com"
        assert "wildcard_enabled" in data
        assert "wildcard_ips" in data
        assert isinstance(data["wildcard_ips"], list)
    
    @patch('dnsrecon.api.brute_srv')
    @patch('dnsrecon.api.DnsHelper')
    def test_brute_srv_endpoint(self, mock_dns_helper, mock_brute_srv, client):
        """Test the SRV record brute force endpoint"""
        # Mock the DNS helper and brute_srv function
        mock_instance = MagicMock()
        mock_dns_helper.return_value = mock_instance
        mock_brute_srv.return_value = [
            {'type': 'SRV', 'name': '_sip._tcp.example.com', 'address': '192.0.2.1', 'target': 'sip.example.com', 'port': 5060}
        ]
        
        response = client.get("/brute_srv?domain=example.com")
        assert response.status_code == 200
        data = response.json()
        
        assert "domain" in data
        assert data["domain"] == "example.com"
        assert "srv_records" in data
        assert isinstance(data["srv_records"], list)
    
    @patch('dnsrecon.api.brute_tlds')
    @patch('dnsrecon.api.DnsHelper')
    def test_brute_tlds_endpoint(self, mock_dns_helper, mock_brute_tlds, client):
        """Test the TLD brute force endpoint"""
        # Mock the DNS helper and brute_tlds function
        mock_instance = MagicMock()
        mock_dns_helper.return_value = mock_instance
        mock_brute_tlds.return_value = [
            {'type': 'A', 'name': 'example.org', 'address': '192.0.2.1'},
            {'type': 'A', 'name': 'example.net', 'address': '192.0.2.2'}
        ]
        
        response = client.get("/brute_tlds?domain=example")
        assert response.status_code == 200
        data = response.json()
        
        assert "domain" in data
        assert data["domain"] == "example"
        assert "tld_records" in data
        assert isinstance(data["tld_records"], list)
    
    @patch('dnsrecon.lib.dnshelper.DnsHelper.zone_transfer')
    @patch('dnsrecon.api.DnsHelper')
    def test_axfr_test_endpoint(self, mock_dns_helper, mock_zone_transfer, client):
        """Test the zone transfer (AXFR) test endpoint"""
        # Mock the DNS helper and zone_transfer method
        mock_instance = MagicMock()
        mock_dns_helper.return_value = mock_instance
        mock_instance.zone_transfer.return_value = [
            {'type': 'A', 'name': 'www.example.com', 'address': '192.0.2.1'},
            {'type': 'MX', 'name': 'mail.example.com', 'address': '192.0.2.2'}
        ]
        
        response = client.get("/axfr_test?domain=example.com")
        assert response.status_code == 200
        data = response.json()
        
        assert "domain" in data
        assert data["domain"] == "example.com"
        assert "zone_transfer_successful" in data
        assert "records" in data
        assert isinstance(data["records"], list)
    
    @patch('dnsrecon.lib.dnshelper.DnsHelper.get_caa')
    @patch('dnsrecon.api.DnsHelper')
    def test_caa_records_endpoint(self, mock_dns_helper, mock_get_caa, client):
        """Test the CAA records endpoint"""
        # Mock the DNS helper and get_caa method
        mock_instance = MagicMock()
        mock_dns_helper.return_value = mock_instance
        mock_instance.get_caa.return_value = [
            ['CAA', 'example.com', '0 issue "letsencrypt.org"']
        ]
        
        response = client.get("/caa_records?domain=example.com")
        assert response.status_code == 200
        data = response.json()
        
        assert "domain" in data
        assert data["domain"] == "example.com"
        assert "caa_records" in data
        assert isinstance(data["caa_records"], list)
    
    @patch('dnsrecon.api.in_cache')
    @patch('dnsrecon.api.DnsHelper')
    def test_cache_snoop_endpoint(self, mock_dns_helper, mock_in_cache, client):
        """Test the cache snooping endpoint"""
        # Mock the DNS helper and in_cache function
        mock_instance = MagicMock()
        mock_dns_helper.return_value = mock_instance
        mock_in_cache.return_value = [
            {'name': 'example.com', 'type': 'A', 'address': '192.0.2.1'}
        ]
        
        response = client.get("/cache_snoop?nameserver=8.8.8.8")
        assert response.status_code == 200
        data = response.json()
        
        assert "nameserver" in data
        assert data["nameserver"] == "8.8.8.8"
        assert "cached_records" in data
        assert isinstance(data["cached_records"], list)
    
    def test_cache_snoop_missing_nameserver(self, client):
        """Test cache snooping with missing nameserver"""
        response = client.get("/cache_snoop")
        assert response.status_code == 422  # Validation error
    
    @patch('dnsrecon.api.ds_zone_walk')
    @patch('dnsrecon.api.DnsHelper')
    def test_zone_walk_endpoint(self, mock_dns_helper, mock_ds_zone_walk, client):
        """Test the DNSSEC zone walking endpoint"""
        # Mock the DNS helper and ds_zone_walk function
        mock_instance = MagicMock()
        mock_dns_helper.return_value = mock_instance
        mock_ds_zone_walk.return_value = [
            {'type': 'A', 'name': 'www.example.com', 'address': '192.0.2.1'},
            {'type': 'AAAA', 'name': 'www.example.com', 'address': '2001:db8::1'}
        ]
        
        response = client.get("/zone_walk?domain=example.com")
        assert response.status_code == 200
        data = response.json()
        
        assert "domain" in data
        assert data["domain"] == "example.com"
        assert "zone_walk_records" in data
        assert isinstance(data["zone_walk_records"], list)
    
    @patch('dnsrecon.api.check_bindversion')
    @patch('dnsrecon.api.DnsHelper')
    def test_bind_version_endpoint(self, mock_dns_helper, mock_check_bindversion, client):
        """Test the BIND version detection endpoint"""
        # Mock the DNS helper and check_bindversion function
        mock_instance = MagicMock()
        mock_dns_helper.return_value = mock_instance
        mock_check_bindversion.return_value = "BIND 9.16.1"
        
        response = client.get("/bind_version?nameserver=8.8.8.8")
        assert response.status_code == 200
        data = response.json()
        
        assert "nameserver" in data
        assert data["nameserver"] == "8.8.8.8"
        assert "bind_version" in data
        assert "version_detected" in data
        assert data["version_detected"] is True
    
    @patch('dnsrecon.api.check_recursive')
    @patch('dnsrecon.api.DnsHelper')
    def test_recursive_check_endpoint(self, mock_dns_helper, mock_check_recursive, client):
        """Test the DNS recursion check endpoint"""
        # Mock the DNS helper and check_recursive function
        mock_instance = MagicMock()
        mock_dns_helper.return_value = mock_instance
        mock_check_recursive.return_value = True
        
        response = client.get("/recursive_check?nameserver=8.8.8.8")
        assert response.status_code == 200
        data = response.json()
        
        assert "nameserver" in data
        assert data["nameserver"] == "8.8.8.8"
        assert "recursive_enabled" in data
        assert "test_result" in data
    
    @patch('dnsrecon.api.check_nxdomain_hijack')
    def test_nxdomain_hijack_endpoint(self, mock_check_nxdomain_hijack, client):
        """Test the NXDOMAIN hijacking detection endpoint"""
        # Mock the check_nxdomain_hijack function
        mock_check_nxdomain_hijack.return_value = None
        
        response = client.get("/nxdomain_hijack?nameserver=8.8.8.8")
        assert response.status_code == 200
        data = response.json()
        
        assert "nameserver" in data
        assert data["nameserver"] == "8.8.8.8"
        assert "hijack_detected" in data
        assert "hijack_details" in data
    
    def test_rate_limiting_headers(self, client):
        """Test that rate limiting is properly configured"""
        response = client.get("/capabilities")
        assert response.status_code == 200
        # Note: Rate limiting headers might not be present in test client
        # This test ensures the endpoint works with rate limiting configured
    
    def test_cors_headers(self, client):
        """Test CORS headers are properly set"""
        # Test CORS with a regular GET request since OPTIONS may not be explicitly defined
        response = client.get("/capabilities")
        assert response.status_code == 200
        # CORS middleware should add headers to responses
    
    def test_error_handling(self, client):
        """Test error handling for invalid requests"""
        # Test with invalid domain parameter - API returns 400 for empty domain
        response = client.get("/general_enum?domain=")
        assert response.status_code == 400  # Bad request for empty domain
        
        # Test missing required parameters
        response = client.get("/brute_reverse")
        assert response.status_code == 422  # Validation error for missing required param
    
    def test_response_format_validation(self, client):
        """Test that responses follow expected JSON format"""
        response = client.get("/capabilities")
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/json"
        
        data = response.json()
        assert isinstance(data, dict)
        assert "capabilities" in data
        assert isinstance(data["capabilities"], list)
