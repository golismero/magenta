#!/usr/bin/python3

import sys
import json
import socket
import os.path
import traceback

from libnmap.parser import NmapParser

# Try to parse the IANA service descriptions.
# If missing just ignore this feature.
IANA_DESCRIPTIONS_FULL = {}
IANA_DESCRIPTIONS_PORTS = {}
IANA_DESCRIPTIONS_NAMES = {}
HTTP_DESC = None
HTTP_ALT_DESC = None
def parse_iana_descriptions(jsonObj):
    global IANA_DESCRIPTIONS_FULL
    global IANA_DESCRIPTIONS_PORTS
    global IANA_DESCRIPTIONS_NAMES
    for srv in jsonObj:
        n = srv.get("name", None)
        po = srv.get("port", None)
        pr = srv.get("protocol", None)
        d = srv.get("description", n)
        if not d:
            continue
        if n and po and pr:
            IANA_DESCRIPTIONS_FULL[(n, po, pr)] = d
        if n and po:
            IANA_DESCRIPTIONS_PORTS[(n, po)] = d
        if n:
            IANA_DESCRIPTIONS_NAMES[n] = d
def get_iana_description(name, port, proto):
    port = str(port)
    desc = IANA_DESCRIPTIONS_FULL.get((name, port, proto), None)
    if not desc:
        desc = IANA_DESCRIPTIONS_PORTS.get((name, port), None)
        if not desc:
            desc = IANA_DESCRIPTIONS_NAMES.get(name, None)
            if not desc:
                desc = name
    return desc
try:
    with open(os.path.join(os.path.dirname(__file__), "iana-descriptions.json")) as fd:
        parse_iana_descriptions(json.load(fd))
    HTTP_DESC = get_iana_description("http", 80, "tcp")
    HTTP_ALT_DESC = get_iana_description("http-alt", 8080, "tcp")
except Exception:
    traceback.print_exc()

# This function parses a single host from the Nmap output.
def parse_host(nmap_report, nmap_host):
    host = {}

    # Ignore hosts that are down.
    if not nmap_host.is_up():
        return

    # Add the IPv4 and IPv6 addresses of the host.
    # If neither is present, ignore the host (should not happen).
    if not nmap_host.ipv4 and not nmap_host.ipv6:
        sys.stderr.write("WARNING: Skipped malformed host: %r\n" % nmap_host)
        return
    if nmap_host.ipv4:
        host["ipv4"] = nmap_host.ipv4
    if nmap_host.ipv6:
        host["ipv6"] = nmap_host.ipv6

    # Parse the port scanning data.
    services = []
    for srv in nmap_host.services:
        m = {}
        if srv.port: m["port"] = srv.port
        if srv.protocol: m["protocol"] = srv.protocol
        if srv.tunnel: m["ssl"] = (srv.tunnel == 'ssl')
        if srv.state: m["state"] = srv.state
        if srv.service and srv.service != "unknown": m["service"] = srv.service
        if srv.cpelist: m["cpe"] = [cpe.cpestring for cpe in srv.cpelist]
        services.append(m)

    # Add the scanned ports.
    if services: host["services"] = services

    # Return the scanned host.
    return host

# Look for vulnerabilities in the Nmap scan output.
TLS_IANA = ['3par-mgmt-ssl', 'amqps', 'amt-redir-tls', 'amt-soap-https', 'appserv-https', 'armcenterhttps', 'asap-sctp-tls', 'asap-tcp-tls', 'babel-dtls', 'bsfsvr-zn-ssl', 'can-ferret-ssl', 'can-nds-ssl', 'caspssl', 'coaps', 'commtact-https', 'compaq-https', 'cops-tls', 'corba-iiop-ssl', 'csvr-sslproxy', 'davsrcs', 'ddm-ssl', 'diameters', 'dicom-tls', 'docker-s', 'domain-s', 'ehs-ssl', 'enpp', 'enrp-sctp-tls', 'ethernet-ip-s', 'etlservicemgr', 'ftps', 'ftps-data', 'giop-ssl', 'gre-udp-dtls', 'hassle', 'hncp-dtls-port', 'https', 'https-alt', 'https-proxy', 'https-wmap', 'iadt-tls', 'ibm-diradm-ssl', 'ice-slocation', 'ice-srouter', 'icpps', 'ieee-mms-ssl', 'imaps', 'imqstomps', 'imqtunnels', 'inetfs', 'initlsmsad', 'intrepid-ssl', 'ipfixs', 'ipps', 'ircs-u', 'iss-mgmt-ssl', 'jboss-iiop-ssl', 'jt400-ssl', 'ldaps', 'linktest-s', 'llsurfup-https', 'lorica-in-sec', 'lorica-out-sec', 'mipv6tls', 'mpls-udp-dtls', 'msft-gc-ssl', 'netconf-ch-ssh', 'netconf-ch-tls', 'netconf-ssh', 'netconf-tls', 'netconfsoaphttp', 'networklenss', 'njenet-ssl', 'nntps', 'nsiiops', 'odette-ftps', 'onep-tls', 'oob-ws-https', 'opcua-tls', 'oracleas-https', 'orbix-cfg-ssl', 'orbix-loc-ssl', 'pcsync-https', 'plysrv-https', 'pon-ictp', 'pop3s', 'pt-tls', 'qmtps', 'radsec', 'restconf-ch-tls', 'rets-ssl', 'rid', 'rpki-rtr-tls', 'saphostctrls', 'sdo-ssh', 'sdo-tls', 'seclayer-tls', 'secure-ts', 'sips', 'sitewatch-s', 'smartcard-tls', 'snif', 'snmpdtls', 'snmpdtls-trap', 'snmpssh', 'snmpssh-trap', 'snmptls', 'snmptls-trap', 'spss', 'sqlexec-ssl', 'ssh', 'ssh-mgmt', 'sshell', 'sslp', 'ssm-cssps', 'ssm-els', 'ssslic-mgr', 'ssslog-mgr', 'stun-behaviors', 'stuns', 'submissions', 'sun-sr-https', 'sun-user-https', 'sunwebadmins', 'suucp', 'synapse-nhttps', 'syncserverssl', 'syslog-tls', 'telnets', 'tftps', 'tl1-raw-ssl', 'tl1-ssh', 'topflow-ssl', 'ttc-ssl', 'tungsten-https', 'turns', 'vipera-ssl', 'vt-ssl', 'wap-push-https', 'wbem-exp-https', 'wbem-https', 'wsm-server-ssl', 'wsmans', 'wso2esb-console', 'xnm-ssl', 'xtlserv', 'xtrms', 'z-wave-s']
def get_open_plaintext_ports(host):

    # Report open ports that do not use SSL.
    # 
    # This is tricky since the scan may have been run without service detection. My plan is:
    #
    #   1) if there is at least one "ssl" property, we can assume detection was performed.
    #   2) if not, we can assume otherwise, so let's use the IANA name to figure our if they're encrypted or not.
    #   3) if the IANA names are missing too, we can assume the default port mapping.
    #
    # This is slightly inaccurate but I don't know how to do better with the information given.

    ports = []
    services = host.get("services", [])
    if services:
        has_sv = False
        for srv in services:
            if "ssl" in srv:
                has_sv = True
                break
        for srv in services:
            if "state" not in srv or srv["state"] != "open":
                continue
            if "service" in srv:
                name = srv["service"]
            else:
                try:
                    name = socket.getservbyport(int(srv["port"]), srv["protocol"])
                except:
                    continue
            if (has_sv and "ssl" not in srv) or (not has_sv and name not in TLS_IANA):
                desc = get_iana_description(name, srv["port"], srv["protocol"])
                if not desc:
                    desc = name
                if "ipv4" in host:
                    ports.append((host["ipv4"], srv["port"], srv["protocol"], desc))
                if "ipv6" in host:
                    ports.append((host["ipv6"], srv["port"], srv["protocol"], desc))
    return ports

# Determine if http is available in this host.
def has_http(host):
    services = host.get("services", [])
    if services:
        for srv in services:
            if srv.get("service", None) == "http" or srv["port"] == 80:
                return True
            if srv.get("service", None) in ("http-alt", "http-proxy") or srv["port"] == 8080:
                return True
    return False

# Determine if https is available in this host.
def has_https(host):
    services = host.get("services", [])
    if services:
        for srv in services:
            if srv.get("service", None) == "https" or srv["port"] == 443:
                return True
            if srv.get("service", None) == ("https-alt", "https-proxy") or srv["port"] == 8443:
                return True
    return False

# Entry point.
def main():

    # Parse the Nmap report using libnmap.
    # https://libnmap.readthedocs.io/en/latest/index.html
    nmap_report = NmapParser.parse(sys.stdin.read())

    # This will be our output array.
    hosts = []
    vulns = []

    # Parse the input nmap scan results.
    for nmap_host in nmap_report.hosts:
        host = parse_host(nmap_report, nmap_host)
        if host is not None:
            hosts.append(host)

    # Report all plaintext open ports as a vulnerability.
    # If it's just port 80 and there is 443 open too, rate it as low.
    # In any other scenario rate it as high.
    severity = "low"
    plaintext_ports = []
    for host in hosts:
        ports_found = get_open_plaintext_ports(host)
        if not ports_found:
            continue
        plaintext_ports.extend(ports_found)
        if severity == "high":
            continue
        if has_http(host) and not has_https(host):
            severity = "high"
        else:
            if HTTP_DESC is not None and HTTP_ALT_DESC is not None:
                for addr, port, proto, desc in ports_found:
                    if desc:
                        if desc not in (HTTP_DESC, HTTP_ALT_DESC):
                            severity = "high"
                            break
                    else:
                        if port not in (80, 8080):
                            severity = "high"
                            break
            else:
                for addr, port, proto, desc in ports_found:
                    if port not in (80, 8080):
                        severity = "high"
                        break
    plaintext_ports.sort()
    if plaintext_ports:
        pp = []
        for addr, port, proto, desc in plaintext_ports:
            p = {
                "address": addr,
                "port": "%s/%s" % (port, proto),
            }
            if desc:
                p["service"] = desc
            pp.append(p)
        issue = {
            "tools": ["nmap"],
            "template": "cleartext_open_ports",
            "severity": severity,
            "affects": ["%s:%s/%s" % x[:3] for x in plaintext_ports],
            "plaintext_ports": pp,
        }
        vulns.append(issue)

    # Report vulnerabilities found by Nmap scripts.
    #
    #
    # TODO
    #
    #

    # Convert the objects array to JSON and send it over stdout.
    json.dump(vulns, sys.stdout)

if __name__ == "__main__":
    main()
