#! /usr/bin/env python3

"""
    pybinaryedge
    ~~~~~~~~~~~~

    Python 3 Wrapper for the BinaryEdge API https://www.binaryedge.io/
    https://github.com/Te-k/pybinaryedge

    :copyright: Tek
    :license: MIT Licence

"""

import requests
import re
import ipaddress


class BinaryEdgeException(Exception):
    """
    Exception raised if a request to BinaryEdge returns anything else than 200
    """
    def __init__(self, message):
        self.message = message
        Exception.__init__(self, message)


class BinaryEdgeNotFound(BinaryEdgeException):
    """
    Exception raised if a request to BinaryEdge returns a 404 code
    """
    def __init__(self):
        self.message = 'Search term not found'
        BinaryEdgeException.__init__(self, self.message)


class BinaryEdge(object):
    def __init__(self, key):
        self.key = key
        self.base_url = 'https://api.binaryedge.io/v2/'
        self.ua = 'pybinaryedge https://github.com/Te-k/pybinaryedge'

    def _get(self, url, params={}):
        headers = {'X-Key': self.key, 'User-Agent': self.ua}
        r = requests.get(self.base_url + url, params=params, headers=headers)
        if r.status_code == 200:
            return r.json()
        else:
            if r.status_code == 404:
                raise BinaryEdgeNotFound()
            else:
                raise BinaryEdgeException(
                    'Invalid return code %i' % r.status_code
                )

    def _is_ip(self, ip):
        """
        Test that the given string is an IPv4/IPv6 address or CIDR

        Args:
            ip: IP address

        Returns:
            a string containing the IP address without bracket

        Raises:
            ValueError: if the string given is not a valid IPv4 address
        """
        try:
            return str(ipaddress.ip_address(ip))
        except:
            pass

        try:
            return str(ipaddress.ip_network(ip,strict=False))
        except:
            raise ValueError('Invalid IP address')

    def user(self):
        """
        User Information
        Return details about your current subscription package.

        https://docs.binaryedge.io/api-v2/#v2usersubscription
        """
        return self._get("user/subscription")

    def host(self, ip):
        """
        Details about an Host. List of recent events for the specified host,
        including details of exposed ports and services.
        https://docs.binaryedge.io/api-v2/#host

        Args:
            ip: IP address (string)

        Returns:
            A dict created from the JSON returned by BinaryEdge

        Raises:
            BinaryEdgeException: if anything else than 200 is returned by BE
        """
        return self._get('query/ip/' + self._is_ip(ip))

    def host_vulnerabilities(self, ip):
        """
        Give list of CVE vulnerabilities that may affect a given IP

        Args:
            ip: IP address (string)

        Returns:
            A dict created from the JSON returned by BinaryEdge

        Raises:
            BinaryEdgeException: if anything else than 200 is returned by BE
        """
        return self._get('query/cve/ip/' + self._is_ip(ip))

    def host_historical(self, ip):
        """
        Details about an Host, with data up to 6 months.
        List of events for the specified host, with events for each time that:
        * A port was detected open
        * A service was found running
        * Other modules were successfully executed
        https://docs.binaryedge.io/api-v2/#v2queryiphistoricaltarget

        Args:
            ip: IPv4 address

        Returns:
            A dict created from the JSON returned by BinaryEdge

        Raises:
            BinaryEdgeException: if anything else than 200 is returned by BE
        """
        return self._get('query/ip/historical/' + self._is_ip(ip))

    def host_search(self, query, page=1, only_ips = 0):
        """
        Events based on a Query. List of recent events for the given query,
        including details of exposed ports and services. Can be used with
        specific parameters and/or full-text search.
        https://docs.binaryedge.io/api-v2/#v2querysearch

        Args:
            query: Search query in BinaryEdge
            page: page number (Optional, Max = 1000)

        Returns:
            A dict created from the JSON returned by BinaryEdge

        Raises:
            BinaryEdgeException: if anything else than 200 is returned by BE
        """
        return self._get('query/search', params={'query': query, 'page': page, "only_ips" : only_ips})

    def host_score(self, ip):
        """
        IP Risk Score. Scoring is based on all information found on
        our databases regarding an IP and refers to the level of exposure
        of a target, i.e, the higher the score, the greater the risk exposure
        https://docs.binaryedge.io/api-v2/#v2queryscoreiptarget

        Args:
            ip: IPv4 address

        Returns:
            A dict created from the JSON returned by BinaryEdge

        Raises:
            BinaryEdgeException: if anything else than 200 is returned by BE
        """
        return self._get('query/score/ip/' + self._is_ip(ip))

    def image_ip(self, ip, page=1):
        """
        Details about Remote Desktops found on an Host. List of screenshots
        and details extracted from them for the specified host, including OCR
        and whether faces were found or not, with data up to 2 months.
        https://docs.binaryedge.io/api-v2/#v2queryimageipip

        Args:
            ip: IPv4 address
            page:  Results page number. Optional. 
                Default page=1

        Returns:
            A dict created from the JSON returned by BinaryEdge

        Raises:
            BinaryEdgeException: if anything else than 200 is returned by BE
        """
        return self._get('query/image/ip/' + self._is_ip(ip), params={ "page" : page })

    def image_search(self, query, page=1):
        """
        Remote Desktops based on a Query. List of screenshots and details
        extracted from them for the given query, including OCR and whether
        faces were found or not. Can be used with specific parameters and/or
        full-text search.
        https://docs.binaryedge.io/api-v2/#v2queryimagesearch

        Args:
            query: Search query in BinaryEdge
            page: page number Max: page=750 (15,000 results) Default 1

        Returns:
            A dict created from the JSON returned by BinaryEdge

        Raises:
            BinaryEdgeException: if anything else than 200 is returned by BE
        """
        return self._get(
            'query/image/search',
            params={'query': query, 'page': page}
        )

    def image_tags(self):
        """
        Get the list of possible tags for the images
        https://docs.binaryedge.io/api-v2/#v2queryimagetags

        Returns:
            A dict created from the JSON returned by BinaryEdge

        Raises:
            BinaryEdgeException: if anything else than 200 is returned by BE
        """
        return self._get('query/image/tags')

    def torrent_search(self,query, page=1):
        """
        Events based on a Query. List of recent events for the given query, including details of the peer and torrent.
        Can be used with specific parameters and/or full-text search.
        https://docs.binaryedge.io/api-v2/#v2queryimagesearch

        Args:
            query: Search query in BinaryEdge
            page: page number

        Returns:
            A dict created from the JSON returned by BinaryEdge

        Raises:
            BinaryEdgeException: if anything else than 200 is returned by BE
        """
        return self._get('query/torrent/search',params = { "query" : query, "page" : page })
    
    def torrent_search_stats(self, query, type, days = 90 , order = "desc"):
        """
        Statistics of events for the given query. 
        Can be used with specific parameters and/or full-text search.

        Args : 
            query: Search query in BinaryEdge
            type : Type of statistic we want to obtain. Possible types include:ports, countries, asn, ips, rdns, categories, names.
            days: Optional. Number of days to get the stats for. For example, days=1 for the last day of data. Default 90. Max = 90
            order: Optional. Whether to sort descendently or ascendently to get the top.Values can be asc, desc. Deafult desc.

        Returns:
            A dict created from the JSON returned by BinaryEdge

        Raises:
            BinaryEdgeException: if anything else than 200 is returned by BE
        """
        return self._get('query/torrent/search/stats', params = { "query" : query, "type" : type, "days" : days, "order" : order })



    def torrent_ip(self, ip):
        """
        Details about torrents transferred by an Host. List of recent
        torrent events for the specified host, including details of the
        peer and torrent.
        https://docs.binaryedge.io/api-v2/#v2querytorrentiptarget

        Args:
            ip: IPv4 address

        Returns:
            A dict created from the JSON returned by BinaryEdge

        Raises:
            BinaryEdgeException: if anything else than 200 is returned by BE
        """
        return self._get('query/torrent/ip/' + self._is_ip(ip))

    def torrent_historical_ip(self, ip):
        """
        Details about torrents transferred by an Host, with data up to 6 months
        List of torrent events for the specified host, with events for each
        time that a new transfer was detected on the DHT.
        https://docs.binaryedge.io/api-v2/#v2querytorrenthistoricaltarget

        Args:
            ip: IPv4 address

        Returns:
            A dict created from the JSON returned by BinaryEdge

        Raises:
            BinaryEdgeException: if anything else than 200 is returned by BE
        """
        return self._get('query/torrent/historical/' + self._is_ip(ip))

    def dataleaks_email(self, email):
        """
        Allows you to search across multiple data breaches to see if any of
        your email addresses has been compromised.
        https://docs.binaryedge.io/api-v2/#v2querydataleaksemailemail

        Args:
            email: email address

        Returns:
            A dict created from the JSON returned by BinaryEdge

        Raises:
            BinaryEdgeNotFound: if the email address is not found by BE
            BinaryEdgeException: if anything else than 200 is returned by BE
        """
        return self._get('query/dataleaks/email/' + email)

    def dataleaks_organization(self, domain):
        """
        Verify how may emails are affected by dataleaks for a specific domain
        We don't provide the list of affected emails.
        https://docs.binaryedge.io/api-v2/#v2querydataleaksorganizationdomain

        Args:
            domain: Verify which dataleaks affect the target domain.

        Returns:
            A dict created from the JSON returned by BinaryEdge

        Raises:
            BinaryEdgeException: if anything else than 200 is returned by BE
        """
        return self._get('query/dataleaks/organization/' + domain)

    def dataleaks_info(self,leak = None):
        """
        Get the list of dataleaks our platform keeps track.
        https://docs.binaryedge.io/api-v2/#v2querydataleaksinfo
        
        Args:
            leak: Return information about a specific dataleak.
                If not used will return all.

        Returns:
            A dict created from the JSON returned by BinaryEdge

        Raises:
            BinaryEdgeException: if anything else than 200 is returned by BE
        """
        args = {}
        
        if leak:
            args["leak"] = leak
        
        return self._get('query/dataleaks/info', params = args)

    def domain_subdomains(self, domain, page=1):
        """
        Get a list of known subdomains for this domain
        https://docs.binaryedge.io/api-v2/#v2querydomainssubdomaintarget

        Args:
            domain: domain queried
            page: page result (default is 1)
                Max: page=500

        Returns:
            A dict created from the JSON returned by BinaryEdge

        Raises:
            BinaryEdgeException: if anything else than 200 is returned
        """
        return self._get(
            'query/domains/subdomain/' + domain,
            params={'page': page}
        )

    def domain_dns(self, domain, page=1):
        """
        Return list of dns results known from the target domain.
        https://docs.binaryedge.io/api-v2/#v2querydomainsdnstarget

        Args:
            domain: domain queried
            page: page result (default is 1)
                Max = 500

        Returns:
            A dict created from the JSON returned by BinaryEdge

        Raises:
            BinaryEdgeException: if anything else than 200 is returned
        """
        return self._get('query/domains/dns/' + domain, params={'page': page})

    def domain_ip(self, ip, page=1):
        """
        Return records that have the specified IP in their A or AAAA records.
        https://docs.binaryedge.io/api-v2/#v2querydomainsiptarget

        Args:
            IP: IP address queried
            page: page result (default is 1)
                Max = 500

        Returns:
            A dict created from the JSON returned by BinaryEdge

        Raises:
            BinaryEdgeException: if anything else than 200 is returned
        """
        return self._get(
            'query/domains/ip/' + self._is_ip(ip),
            params={'page': page}
        )

    def domain_search(self,query, page=1):
        """
        List of Domains/DNS data based on a Query. Can be used 
        with specific parameters and/or full-text search. 
        Possible types of records currently available:
            >> A
            >> AAAA
            >> NS
            >> MX
            >> CNAME
            >> TXT
        
        Args : 
            query: String used to query our data
            page: Results page number Default 1
                Max = 500

        Returns:
            A dict created from the JSON returned by BinaryEdge

        Raises:
            BinaryEdgeException: if anything else than 200 is returned

        """

        return self._get("query/domains/search", params = { "query" : query, "page" : page })

    def domain_enumeration(self, domain, validate=0, total = None):
        """
        This endpoint attempts to enumerate subdomains from a larger dataset. 
        
        The validate flag can be used to have all subdomains resolved on the fly and only those with DNS entries behind them returned.

        Args :
            domain: [string] Domain you want to enumerate
            
            validate: [any] Optional. If validate=1, forces all subdomains to be resolved on request and only live 
            subdomains to be returned Default: validate=0

            total: [int] Optional. Return at most the number of results specified 
            Default: undefined, return all results
        
        Returns : 
            A dict created from the JSON returned by BinaryEdge

        Raises:
            BinaryEdgeException: if anything else than 200 is returned
        """
        args = {}
        args["validate"] = validate
        
        if total:
            args["total"] = total
        
        return self._get( f"query/domains/enumeration/{domain}", params = args )

    def domain_homoglyphs(self, domain, validate=0, total = None):
        """
        This endpoint generates a list of homoglyphs for a base domain.
        
        The validate flag can be used to have all homoglyphs resolved on the fly and only those
        with DNS entries behind them returned.

        Args :
            domain: [string] Domain you want to enumerate
            
            validate: [any] Optional. If validate=1, forces all subdomains to be resolved on request and only live 
            subdomains to be returned Default: validate=0

            total: [int] Optional. Return at most the number of results specified 
            Default: undefined, return all results
        
        Returns : 
            A dict created from the JSON returned by BinaryEdge

        Raises:
            BinaryEdgeException: if anything else than 200 is returned
        """
        args = {}
        args["validate"] = validate
        
        if total:
            args["total"] = total
        
        return self._get( f"query/domains/homoglyphs/{domain}", params = args )
    
    def sensor_ip(self, target):
        """
        Details about an Scanner. List of recent events form the specified host,
        including details of scanned ports, payloads and tags.
        https://docs.binaryedge.io/api-v2/#v2querysensorsiptarget

        Args:
            target: [String] target IP address or CIDR up to /24

        Returns:
            A dict created from the JSON returned by BinaryEdge

        Raises:
            BinaryEdgeException: if anything else than 200 is returned
            BinaryEdgeNotFound: if the target has not been seen by sensors
        """
        return self._get('query/sensors/ip/%s' % target)

    def sensor_search(self, query, page=1, days = 30, only_ips = 0):
        """
        Events based on a Query. List of recent events for the given query,
        including details of scanned ports, payloads and tags. Can be used
        with specific parameters and/or full-text search.
        https://docs.binaryedge.io/api-v2/#v2querysensorssearch

        Args:
            query: String used to query our data. If no filters are
                used, it will perform a full-text search on the entire events
            page: Optional. Default 1, Maximum: 500 (10,000 results)
            days: Optional. Number of days to get the stats for. For example, days=1 for the last day of data.
                Default: days=30
            only_ips: Optional. If only_ips=1, only output IP addresses, ports and protocols.
                Default: only_ips=0
        Returns:
            A dict created from the JSON returned by BinaryEdge

        Raises:
            BinaryEdgeException: if anything else than 200 is returned

        Example:
            be.sensor_search('tags:ssh_scanner')
        """
        return self._get(
                'query/sensors/search',
                params={'query': query, 'page': page, "only_ips" : only_ips, "days" : days}
        )

    def sensor_search_stats(self, query, type, days=60, order='desc'):
        """
        Statistics of events for the given query. Can be used with specific
        parameters and/or full-text search.
        https://docs.binaryedge.io/api-v2/#v2querysensorssearchstats

        Args:
            query: [String] String used to query our data. If no filters are
                used, it will perform a full-text search on the entire events.
            type: [String] Type of statistic we want to obtain.
                Possible types include: ports, tags, countries, asn, ips,
                payloads, http_path.
            days: [Integer] Number of days to get the stats for.
                For example days=1 for the last day of data.
            order: [String] Optional. Whether to sort descendently or ascendently to get the top.
                Values desc, asc. Default: order=desc

        Returns:
            A dict created from the JSON returned by BinaryEdge

        Raises:
            BinaryEdgeException: if anything else than 200 is returned
                or if type is not correct

        Example:
            be.sensor_search_stats('tags:ssh_scanner', 'ports')
        """
        if type not in ['ports', 'tags', 'countries', 'asn', 'ips',
                    'payloads', 'http_path']:
            raise BinaryEdgeException('Invalid type')
        return self._get('query/sensors/search/stats',
                params={
                    'query': query,
                    'type': type,
                    'days': days,
                    'order': order
                }
        )

    def sensor_tag(self, tag, days = 1):
        """
        Get a list of IPs that have been associated with a specific TAG. 
        See List of Tags

        Args
            tag: [String] Tag you want to get the list of IPs related to. example: MALICIOUS
            days: [Integer] : Number of days to get the stats for. For example days=1 for the last day of data. 
                Default: 1. Max 60.
        
        Returns:
            A list returned by BinaryEdge

        Raises:
            BinaryEdgeException: if anything else than 200 is returned by BE
        """
        return self._get("query/sensors/tag/" + tag, params={ "days" : days } )

    def stats(self, query, type, order = 'desc'):
        """
        Statistics of recent events for the given query. Can be used with
        specific parameters and/or full-text search.
        https://docs.binaryedge.io/api-v2/#v2querysearchstats

        Args:
            query: String used to query our data
            type: Type of statistic we want to obtain. Possible types include:
                ports, products, versions, tags, services, countries, asn.
            order :  Whether to sort descendently or ascendently to get the top (Optional, default desc)
                values can be desc,asc
        
        Returns:
            A dict created from the JSON returned by BinaryEdge

        Raises:
            BinaryEdgeException: if anything else than 200 is returned
        """
        if type not in ['ports', 'products', 'versions', 'tags', 'services',
                'countries', 'asn']:
            raise BinaryEdgeException('Invalid type')
        return self._get(
            'query/search/stats',
            params={
                'query': query,
                'type': type,
                'order' : order
            }
        )
