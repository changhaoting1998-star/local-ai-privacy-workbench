"""Trusted process-side deployment policy; no request header can select a profile."""
from __future__ import annotations
from dataclasses import dataclass
import ipaddress
from urllib.parse import urlsplit

RFC1918=tuple(ipaddress.ip_network(x) for x in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))
@dataclass(frozen=True)
class Deployment:
    mode:str='loopback'
    origin:str='http://127.0.0.1:8910'
    cidr:str=''
    def __post_init__(self):
        if self.mode=='loopback':
            if self.origin!='http://127.0.0.1:8910' or self.cidr:raise ValueError('Loopback policy is fixed')
        elif self.mode=='lan_https':
            try:
                parsed=urlsplit(self.origin);ip=ipaddress.ip_address(parsed.hostname or '');network=ipaddress.ip_network(self.cidr,strict=True)
                if parsed.scheme!='https' or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:raise ValueError()
                if parsed.port is None or not 1024<=parsed.port<=65535 or ip.version!=4 or network.version!=4:raise ValueError()
                if not any(network.subnet_of(n) for n in RFC1918) or ip not in network or ip in (network.network_address,network.broadcast_address):raise ValueError()
                if self.origin!=f'https://{ip}:{parsed.port}':raise ValueError()
            except Exception:raise ValueError('LAN requires exact HTTPS private IPv4:port and matching RFC1918 CIDR') from None
        else:raise ValueError('Unknown deployment mode')
    @classmethod
    def lan(cls,origin,cidr):return cls('lan_https',origin,cidr)
    @property
    def secure(self):return self.mode=='lan_https'
    @property
    def host(self):return urlsplit(self.origin).hostname
    @property
    def port(self):return urlsplit(self.origin).port
    @property
    def callback(self):return self.origin+'/api/auth/feishu/callback'
    @property
    def authority(self):return urlsplit(self.origin).netloc
    def allows_client(self,host):
        if not self.secure:return host in ('127.0.0.1','::1','testclient')
        try:return ipaddress.ip_address(host) in ipaddress.ip_network(self.cidr)
        except ValueError:return False
    def canonical(self,request):return request.headers.get('host')==self.authority and request.url.scheme==urlsplit(self.origin).scheme
