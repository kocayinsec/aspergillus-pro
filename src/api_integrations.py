import asyncio
import aiohttp
import logging
import time
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import json

@dataclass
class ThreatIntelligence:
    ip_address: str
    is_malicious: bool
    reputation_score: Optional[int]
    categories: List[str]
    source: str
    last_seen: Optional[str]
    country: Optional[str]
    isp: Optional[str]
    additional_info: Dict[str, Any]

class RateLimiter:
    def __init__(self, max_requests: int = 4, time_window: int = 60):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = []

    async def wait_if_needed(self):
        """Wait if rate limit would be exceeded"""
        current_time = time.time()
        
        # Remove old requests
        self.requests = [req_time for req_time in self.requests 
                        if current_time - req_time < self.time_window]
        
        if len(self.requests) >= self.max_requests:
            sleep_time = self.time_window - (current_time - self.requests[0])
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)
                self.requests = self.requests[1:]
        
        self.requests.append(current_time)

class VirusTotalAPI:
    def __init__(self, api_key: str, rate_limit: int = 4):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.rate_limiter = RateLimiter(max_requests=rate_limit)
        self.logger = logging.getLogger(__name__)
        self.session = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def check_ip_reputation(self, ip_address: str) -> Optional[ThreatIntelligence]:
        """Check IP reputation using VirusTotal API"""
        if not self.api_key:
            self.logger.warning("VirusTotal API key not configured")
            return None

        try:
            await self.rate_limiter.wait_if_needed()
            
            params = {
                'apikey': self.api_key,
                'ip': ip_address
            }
            
            url = f"{self.base_url}/ip-address/report"
            
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_vt_response(ip_address, data)
                elif response.status == 204:
                    self.logger.debug(f"Rate limit hit for VirusTotal API")
                    return None
                else:
                    self.logger.error(f"VirusTotal API error: {response.status}")
                    return None
                    
        except Exception as e:
            self.logger.error(f"Error checking IP reputation with VirusTotal: {e}")
            return None

    def _parse_vt_response(self, ip_address: str, data: Dict[str, Any]) -> ThreatIntelligence:
        """Parse VirusTotal API response"""
        detected_urls = data.get('detected_urls', [])
        detected_samples = data.get('detected_samples', [])
        
        is_malicious = len(detected_urls) > 0 or len(detected_samples) > 0
        
        # Calculate reputation score (0-100, lower is worse)
        reputation_score = 100
        if detected_urls:
            reputation_score -= min(len(detected_urls) * 10, 50)
        if detected_samples:
            reputation_score -= min(len(detected_samples) * 5, 30)
        
        categories = []
        if detected_urls:
            categories.append("malicious_urls")
        if detected_samples:
            categories.append("malware_samples")
        
        return ThreatIntelligence(
            ip_address=ip_address,
            is_malicious=is_malicious,
            reputation_score=max(reputation_score, 0),
            categories=categories,
            source="VirusTotal",
            last_seen=None,
            country=data.get('country'),
            isp=data.get('as_owner'),
            additional_info={
                'detected_urls_count': len(detected_urls),
                'detected_samples_count': len(detected_samples),
                'asn': data.get('asn'),
                'network': data.get('network')
            }
        )

class AbuseIPDBAPI:
    def __init__(self, api_key: str, rate_limit: int = 1000):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.rate_limiter = RateLimiter(max_requests=rate_limit, time_window=86400)  # Daily limit
        self.logger = logging.getLogger(__name__)
        self.session = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def check_ip_reputation(self, ip_address: str) -> Optional[ThreatIntelligence]:
        """Check IP reputation using AbuseIPDB API"""
        if not self.api_key:
            self.logger.warning("AbuseIPDB API key not configured")
            return None

        try:
            await self.rate_limiter.wait_if_needed()
            
            headers = {
                'Key': self.api_key,
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            url = f"{self.base_url}/check"
            
            async with self.session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    result = await response.json()
                    data = result.get('data', {})
                    return self._parse_abuseipdb_response(ip_address, data)
                elif response.status == 429:
                    self.logger.debug(f"Rate limit hit for AbuseIPDB API")
                    return None
                else:
                    self.logger.error(f"AbuseIPDB API error: {response.status}")
                    return None
                    
        except Exception as e:
            self.logger.error(f"Error checking IP reputation with AbuseIPDB: {e}")
            return None

    def _parse_abuseipdb_response(self, ip_address: str, data: Dict[str, Any]) -> ThreatIntelligence:
        """Parse AbuseIPDB API response"""
        abuse_confidence = data.get('abuseConfidencePercentage', 0)
        is_malicious = abuse_confidence > 25  # Threshold for considering IP malicious
        
        categories = []
        usage_type = data.get('usageType')
        if usage_type:
            categories.append(usage_type.lower())
        
        if data.get('tor'):
            categories.append('tor')
        
        return ThreatIntelligence(
            ip_address=ip_address,
            is_malicious=is_malicious,
            reputation_score=100 - abuse_confidence,
            categories=categories,
            source="AbuseIPDB",
            last_seen=data.get('lastReportedAt'),
            country=data.get('countryCode'),
            isp=data.get('isp'),
            additional_info={
                'abuse_confidence': abuse_confidence,
                'usage_type': data.get('usageType'),
                'total_reports': data.get('totalReports'),
                'num_distinct_users': data.get('numDistinctUsers'),
                'is_tor': data.get('tor', False),
                'is_whitelisted': data.get('isWhitelisted', False)
            }
        )

class ThreatIntelligenceAggregator:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.integrations_config = config.get('integrations', {})
        self.enable_api_lookups = self.integrations_config.get('enable_api_lookups', False)
        self.rate_limit = self.integrations_config.get('api_rate_limit', 4)
        
        self.vt_api = None
        self.abuseipdb_api = None
        self.cache = {}  # Simple in-memory cache
        self.cache_ttl = 3600  # 1 hour cache TTL
        
        self.logger = logging.getLogger(__name__)
        
        if self.enable_api_lookups:
            self._initialize_apis()

    def _initialize_apis(self):
        """Initialize API clients"""
        vt_key = self.integrations_config.get('virustotal_api_key')
        abuseipdb_key = self.integrations_config.get('abuseipdb_api_key')
        
        if vt_key:
            self.vt_api = VirusTotalAPI(vt_key, self.rate_limit)
            self.logger.info("VirusTotal API initialized")
        
        if abuseipdb_key:
            self.abuseipdb_api = AbuseIPDBAPI(abuseipdb_key, 1000)  # AbuseIPDB has higher daily limits
            self.logger.info("AbuseIPDB API initialized")

    async def check_ip_reputation(self, ip_address: str) -> List[ThreatIntelligence]:
        """Check IP reputation across all configured sources"""
        if not self.enable_api_lookups:
            return []

        # Check cache first
        cache_key = f"ip_{ip_address}"
        if cache_key in self.cache:
            cached_data, timestamp = self.cache[cache_key]
            if time.time() - timestamp < self.cache_ttl:
                return cached_data

        results = []
        
        # Check VirusTotal
        if self.vt_api:
            try:
                async with self.vt_api as vt:
                    vt_result = await vt.check_ip_reputation(ip_address)
                    if vt_result:
                        results.append(vt_result)
            except Exception as e:
                self.logger.error(f"Error with VirusTotal lookup: {e}")
        
        # Check AbuseIPDB
        if self.abuseipdb_api:
            try:
                async with self.abuseipdb_api as abuse:
                    abuse_result = await abuse.check_ip_reputation(ip_address)
                    if abuse_result:
                        results.append(abuse_result)
            except Exception as e:
                self.logger.error(f"Error with AbuseIPDB lookup: {e}")
        
        # Cache results
        self.cache[cache_key] = (results, time.time())
        
        return results

    def get_consolidated_reputation(self, results: List[ThreatIntelligence]) -> Dict[str, Any]:
        """Consolidate reputation data from multiple sources"""
        if not results:
            return {
                'is_malicious': False,
                'confidence': 0,
                'sources': [],
                'reputation_score': 100
            }

        malicious_votes = sum(1 for result in results if result.is_malicious)
        total_votes = len(results)
        
        # Calculate weighted reputation score
        weighted_score = 0
        total_weight = 0
        
        for result in results:
            if result.reputation_score is not None:
                weight = 1.0
                if result.source == "VirusTotal":
                    weight = 1.2  # Give VirusTotal slightly more weight
                elif result.source == "AbuseIPDB":
                    weight = 1.0
                
                weighted_score += result.reputation_score * weight
                total_weight += weight
        
        avg_reputation = weighted_score / total_weight if total_weight > 0 else 100
        
        # Determine if IP is malicious based on consensus
        is_malicious = malicious_votes >= (total_votes / 2)  # Majority vote
        confidence = (malicious_votes / total_votes) * 100 if total_votes > 0 else 0
        
        # Collect all categories
        all_categories = []
        for result in results:
            all_categories.extend(result.categories)
        
        return {
            'is_malicious': is_malicious,
            'confidence': confidence,
            'sources': [result.source for result in results],
            'reputation_score': int(avg_reputation),
            'categories': list(set(all_categories)),
            'details': [
                {
                    'source': result.source,
                    'is_malicious': result.is_malicious,
                    'reputation_score': result.reputation_score,
                    'categories': result.categories,
                    'country': result.country,
                    'isp': result.isp,
                    'additional_info': result.additional_info
                }
                for result in results
            ]
        }

    async def enrich_threat_alert(self, source_ip: str, target_ip: Optional[str] = None) -> Dict[str, Any]:
        """Enrich threat alert with intelligence data"""
        enrichment = {
            'source_intel': None,
            'target_intel': None
        }
        
        # Check source IP
        if source_ip:
            source_results = await self.check_ip_reputation(source_ip)
            if source_results:
                enrichment['source_intel'] = self.get_consolidated_reputation(source_results)
        
        # Check target IP if provided
        if target_ip:
            target_results = await self.check_ip_reputation(target_ip)
            if target_results:
                enrichment['target_intel'] = self.get_consolidated_reputation(target_results)
        
        return enrichment

    def clear_cache(self):
        """Clear the reputation cache"""
        self.cache.clear()
        self.logger.info("Threat intelligence cache cleared")

    async def bulk_check_ips(self, ip_addresses: List[str]) -> Dict[str, List[ThreatIntelligence]]:
        """Check multiple IPs in parallel with rate limiting"""
        results = {}
        
        # Process IPs in batches to respect rate limits
        batch_size = min(5, self.rate_limit)
        
        for i in range(0, len(ip_addresses), batch_size):
            batch = ip_addresses[i:i + batch_size]
            
            tasks = []
            for ip in batch:
                tasks.append(self.check_ip_reputation(ip))
            
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for ip, result in zip(batch, batch_results):
                if isinstance(result, Exception):
                    self.logger.error(f"Error checking IP {ip}: {result}")
                    results[ip] = []
                else:
                    results[ip] = result
            
            # Small delay between batches
            await asyncio.sleep(1)
        
        return results