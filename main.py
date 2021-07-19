import argparse
import dataclasses
import os
import subprocess
import tempfile
from typing import List, Optional, Set
import xml.etree.ElementTree as ET


@dataclasses.dataclass(frozen=True)
class DiscoveredService:
    port: int
    protocol: str
    name: str
    product: str

    def __repr__(self):
        return f'{self.protocol}/{self.port}: {self.name} {self.product}'


@dataclasses.dataclass(frozen=True)
class InterestingObservation:
    service: DiscoveredService
    message: str

    def __repr__(self):
        return f'Interesting observation of {self.service}: {self.message}'


class Nmap:
    @staticmethod
    def _parse_xml(xml_body: str) -> Set[DiscoveredService]:
        discovered_services = set()

        elem_root = ET.fromstring(xml_body)
        elems_ports = elem_root.findall('./host/ports/port')
        for elem_port in elems_ports:
            elem_service = elem_port.find('./service')
            discovered_services.add(DiscoveredService(
                port=elem_port.attrib["portid"],
                protocol=elem_port.attrib["protocol"],
                name=elem_service.attrib["name"],
                product=elem_service.attrib["product"],
            ))

        return discovered_services

    @staticmethod
    def _exec_nmap(args: List[str], ip: str) -> str:
        filename = 'nmap.xml'
        with tempfile.TemporaryDirectory() as temp_dir:
            subprocess.check_output(['nmap'] + args + f'-oX {os.path.join(temp_dir, filename)} {ip}'.split())
            with open(os.path.join(temp_dir, filename)) as f:
                return f.read()

    @staticmethod
    def fast(ip: str) -> Set[DiscoveredService]:
        xml_body = Nmap._exec_nmap(args='-sC -sV -F'.split(), ip=ip)
        return Nmap._parse_xml(xml_body=xml_body)

    @staticmethod
    def all(ip: str) -> Set[DiscoveredService]:
        xml_body = Nmap._exec_nmap(args='-sC -sV -p-'.split(), ip=ip)
        return Nmap._parse_xml(xml_body=xml_body)


class Nikto:
    @staticmethod
    def execute(ip: str, svc: DiscoveredService) -> Set[InterestingObservation]:
        if svc.name != 'http':
            return set()

        filename = 'nikto.xml'
        with tempfile.TemporaryDirectory() as temp_dir:
            subprocess.check_output(f'nikto -host {ip} -port {svc.port} -output {os.path.join(temp_dir, filename)}'.split())
            with open(os.path.join(temp_dir, filename)) as f:
                xml_body = f.read()

        elem_root = ET.fromstring(xml_body)
        elems_items = elem_root.findall('./scandetails/item')
        return {InterestingObservation(service=svc, message=item.find('description').text) for item in elems_items}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('ip', type=str)
    args = parser.parse_args()

    discovered_services = Nmap.fast(args.ip)
    for svc in discovered_services:
        print(f'Discovered service {svc}')

    interesting_observations = {interesting_obs for svc in discovered_services for interesting_obs in Nikto.execute(args.ip, svc)}
    for obs in interesting_observations:
        print(obs)

    discovered_services = Nmap.all(args.ip) - discovered_services
    for svc in discovered_services:
        print(f'Discovered service {svc}')

    interesting_observations = {interesting_obs for svc in discovered_services for interesting_obs in Nikto.execute(args.ip, svc)}
    for obs in interesting_observations:
        print(obs)
