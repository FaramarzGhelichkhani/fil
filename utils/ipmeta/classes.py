import logging
from typing import List

import plotly.graph_objects as go
import plotly.io as pio
from numerize import numerize
from plotly.subplots import make_subplots

pio.renderers.default = "browser"
logger = logging.getLogger("ip_classification.ip_meta")


class PortDist:
    def __init__(self, port=None, percent=None, traffic=None, hit=None):
        self.port = port
        self.percent = percent
        self.traffic = traffic
        self.hit = hit

    def __repr__(self):
        return str(self.port) + ": (" + str(round(self.percent * 100, 2)) + "%)"

    def dict(self):
        return {'port': self.port, 'percent': self.percent}


class AppDist:
    def __init__(self, app_name=None, valid=None, traffic=None, app_id=None, percent=None):
        self.app_id = app_id
        self.percent = percent
        self.app_name = app_name
        self.valid = valid
        self.traffic = traffic

    def __repr__(self):
        return str(self.app_id) + ": (" + str(numerize.numerize(self.traffic)) + " : " + str(
            round(self.percent * 100, 2)) + "% : " + str(self.app_name) + ")"

    def dict(self):
        return {'app_id': self.app_id, 'percent': self.percent, 'app_name': self.app_name, 'valid': self.valid,
                'traffic': self.traffic}


class DomainDist:
    def __init__(self, domain=None, traffic=None, sub=None, percent=None):
        self.domain = domain
        self.percent = percent
        self.traffic = traffic
        self.sub = sub

    def __repr__(self):
        return str(self.domain) + ": (" + str(numerize.numerize(self.traffic)) + " : " + str(
            round(self.percent * 100, 2)) + "% : " + str(self.sub) + ")"

    def dict(self):
        return {'domain': self.domain, 'traffic': self.traffic, 'percent': self.percent, 'sub': self.sub}



class DnsDist:
    def __init__(self, dns=None, hit=None, sub=None, percent=None):
        self.dns = dns
        self.percent = percent
        self.hit = hit
        self.sub = sub

    def __repr__(self):
        return str(self.dns) + ": (" + str(numerize.numerize(self.hit)) + " : " + str(
            round(self.percent * 100, 2)) + "% : " + str(self.sub) + ")"

    def dict(self):
        return {'dns': self.dns, 'hit': self.hit, 'percent': self.percent, 'sub': self.sub}


class SizeDist:
    def __init__(self, protocol=None, size=None, traffic=None, percent=None):
        self.protocol = protocol
        self.size = size
        self.traffic = traffic
        self.percent = percent

    def __repr__(self):
        return str(self.size) + ": (" + str(numerize.numerize(self.percent)) + ")"

    def dict(self):
        return {'protocol': self.protocol, 'size': self.size, 'traffic': self.traffic, 'percent': self.percent}

class DetectionDist:
    def __init__(self, detection=None, percent=None, traffic=None):
        self.detection = detection
        self.percent = percent
        self.traffic = traffic

    def __repr__(self):
        return str(self.detection) + ": (" + str(round(self.percent, 2)) + "%)"

    def dict(self):
        return {'detection': self.detection, 'percent': self.percent, 'traffic': self.traffic}
class ActiontDist:
    def __init__(self, action=None, percent=None, traffic=None):
        self.action = action
        self.percent = percent
        self.traffic = traffic

    def __repr__(self):
        return str(self.action) + ": (" + str(round(self.percent, 2)) + "%)"

    def dict(self):
        return {'action': self.action, 'percent': self.percent, 'traffic': self.traffic}

class SiteDist:
    def __init__(self, site_name=None, percent=None, traffic=None):
        self.site_name = site_name
        self.percent = percent
        self.traffic = traffic

    def __repr__(self):
        return str(self.site_name) + ": (" + str(round(self.percent, 2)) + "%)"

    def dict(self):
        return {'site_name': self.site_name, 'percent': self.percent, 'traffic': self.traffic}

class ResolvedIP:
    def __init__(self, ip=None, asn=None, country=None, hit=None, sub=None, percent=None, time=None):
        self.ip = ip
        self.asn = asn
        self.country = country
        self.percent = percent
        self.hit = hit
        self.sub = sub
        self.time = time


class ServerIP:
    def __init__(self, ip=None, asn=None, country=None, percent=None, sub=None, traffic=None, time=None):
        self.ip = ip
        self.asn = asn
        self.country = country
        self.traffic = traffic
        self.percent = percent
        self.sub = sub
        self.time = time


class DomainMeta:
    def __init__(
            self, domain: str, resolved_ips: List[ResolvedIP] = None, server_ips: List[ServerIP] = None
    ):
        self.domain = domain
        self.resolved_ips = [] if resolved_ips is None else resolved_ips
        self.server_ips = [] if server_ips is None else server_ips


class IpMeta:

    def __init__(
            self, ip, domain_dist: List[DomainDist] = None, dns_dist: List[DnsDist] = None,
            port_dist: List[PortDist] = None, appiddist: List[AppDist] = None, size_dist: List[SizeDist] = None,
            action_dist: List[ActiontDist] = None,  detection_dist: List[DetectionDist] = None,
            site_dist: List[SiteDist] = None, 
            asn='',bsc=None, bcs=None, hit=None, percent=None, country='', traffic=None, time=None):

        self.ip = ip
        self.domain_dist = [] if domain_dist is None else domain_dist
        self.dns_dist = [] if dns_dist is None else dns_dist
        self.port_dist = [] if port_dist is None else port_dist
        self.appid_dist = [] if appiddist is None else appiddist
        self.size_dist = [] if size_dist is None else size_dist
        self.action_dist = [] if action_dist is None else action_dist
        self.detection_dist = [] if detection_dist is None else detection_dist
        self.site_dist = [] if site_dist is None else site_dist
        self.asn = asn
        self.totalbsc = bsc
        self.totalbcs = bcs
        self.totalhit = hit
        self.totalpercent = percent
        self.country = country
        self.time = time
        self.total_traffic = traffic
       
    def showip(self):
        port_labels = [port_dist.port for port_dist in self.port_dist]
        port_percent = [port_dist.percent for port_dist in self.port_dist]

        app_labels = [appid_dist.app_id for appid_dist in self.appid_dist]
        app_name = [appid_dist.app_name for appid_dist in self.appid_dist]
        app_percent = [appid_dist.percent for appid_dist in self.appid_dist]
        app_traffic = [appid_dist.traffic for appid_dist in self.appid_dist]

        domain_labels = [
            domain_dist.domain for domain_dist in self.domain_dist]
        domain_percent = [
            domain_dist.percent for domain_dist in self.domain_dist]
        domain_traffic = [
            domain_dist.traffic for domain_dist in self.domain_dist]

        dns_labels = [dns_dist.dns for dns_dist in self.dns_dist]
        dns_percent = [dns_dist.percent for dns_dist in self.dns_dist]
        dns_hit = [dns_dist.hit for dns_dist in self.dns_dist]

        byte = [self.totalbsc, self.totalbcs]
        byte_label = ["bsc", "bcs"]

        fig = make_subplots(rows=2, cols=2, specs=[[{"type": "pie"}, {"type": "pie"}],
                                                   [{"type": "pie"}, {"type": "pie"}]],
                            subplot_titles=('', '',
                                            '', '')
                            )

        fig.add_trace(go.Pie(labels=app_name[0:10], values=app_traffic[0:10], showlegend=True, rotation=250,
                             hole=0.5, title="APP_Name_Traffic", textinfo='label+percent', textposition='outside'),
                      row=1, col=1)
        fig.add_trace(
            go.Pie(labels=domain_labels[0:10], values=domain_traffic[0:10], showlegend=True, rotation=270, hole=0.5,
                   title='Domain_Traffic', textinfo='label+percent', textposition='outside', direction='clockwise'),
            row=1, col=2)
        fig.add_trace(go.Pie(labels=dns_labels[0:10], values=dns_hit[0:10], showlegend=True, rotation=70,
                             hole=0.5, title="DNS_Hit", textinfo='label+percent', textposition='outside'), row=2, col=1)
        fig.add_trace(go.Pie(labels=port_labels[0:10], values=port_percent[0:10], showlegend=True,
                             rotation=270, hole=0.3, title="Port_Bytes", textinfo='label+percent'), row=2, col=2)
        fig.add_trace(go.Pie(labels=byte_label, values=byte, showlegend=True, rotation=45,
                             hole=0.8, textinfo='label+percent', textposition='outside'), row=2, col=2)
        fig.show()
