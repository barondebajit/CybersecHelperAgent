import socket
import ipaddress
from google.genai import types

def dns_lookup(domain_name):
    """
    Perform a DNS lookup for the given domain name and return the IP address.
    
    :param domain_name: The domain name to look up.
    :return: The IP address associated with the domain name, or None if not found.
    """
    try:
        ip_address = socket.gethostbyname(domain_name)
        return ip_address
    except socket.gaierror:
        return None
    except Exception as e:
        print(f"Unexpected error during DNS lookup: {e}")
        return None

def reverse_dns_lookup(ip_address):
    """
    Perform a reverse DNS lookup for the given IP address and return the domain name.
    
    :param ip_address: The IP address to look up.
    :return: The domain name associated with the IP address, or None if not found.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror:
        return None
    except socket.gaierror:
        return None
    except Exception as e:
        print(f"Unexpected error during reverse DNS lookup: {e}")
        return None
    
def blacklist_check(ip_address, blacklists=None):
    if blacklists is None:
        blacklists = [
            'zen.spamhaus.org',
            'bl.spamcop.net',
            'dnsbl.sorbs.net',
            'cbl.abuseat.org',
            'psbl.surriel.com',
            'sbl.spamhaus.org',
            'xbl.spamhaus.org',
            'pbl.spamhaus.org'
        ]
    
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        if ip_obj.version != 4:
            return {}
    except ValueError:
        return {}
    
    octets = ip_address.split('.')
    reversed_ip = '.'.join(reversed(octets))
    
    results = {}
    
    for blacklist in blacklists:
        query = f"{reversed_ip}.{blacklist}"
        try:
            socket.gethostbyname(query)
            results[blacklist] = True
        except socket.gaierror:
            results[blacklist] = False
        except Exception:
            results[blacklist] = None
    
    return results

dns_lookup_function = types.FunctionDeclaration(
    name="dns_lookup",
    description="Perform a DNS lookup for the given domain name and return the IP address.",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "domain_name": types.Schema(
                type=types.Type.STRING,
                description="The domain name to look up."
            )
        },
        required=["domain_name"]
    )
)

reverse_dns_lookup_function = types.FunctionDeclaration(
    name="reverse_dns_lookup",
    description="Perform a reverse DNS lookup for the given IP address and return the domain name.",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "ip_address": types.Schema(
                type=types.Type.STRING,
                description="The IP address to look up."
            )
        },
        required=["ip_address"]
    )
)

blacklist_check_function = types.FunctionDeclaration(
    name="blacklist_check",
    description="Check if the given IP address is listed in common DNS blacklists.",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "ip_address": types.Schema(
                type=types.Type.STRING,
                description="The IP address to check against blacklists."
            ),
            "blacklists": types.Schema(
                type=types.Type.ARRAY,
                items=types.Schema(
                    type=types.Type.STRING,
                    description="List of DNS blacklists to check against."
                ),
                description="Optional list of DNS blacklists to check against."
            )
        },
        required=["ip_address"]
    )
)