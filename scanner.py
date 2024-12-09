from scapy.all import *
import socket
import argparse
import ipaddress
import nmap


def get_args():
    parser = argparse.ArgumentParser(
        description="To scan Target ip and thier open ports"
    )
    parser.add_argument("-t", "--target", dest="target", help="Target to scan")
    parser.add_argument("-p", "--port", type=str, dest="port", help="Port to scan")
    options = parser.parse_args()
    if not options.target:
        parser.error("Please specify the target ip address to scan")
    elif not options.port:
        parser.error("Please specify the port or number of ports to scan")
    return options


def ip_scanner(ip):
    response = sr1(IP(dst=ip) / ICMP(), timeout=1, verbose=False)
    print("\n[+] Target  : " + ip)
    if response:
        print("[+] Status   :  up")
        print("[+] Protocol :  TCP")
        return True
    else:
        print("[+] Status : down")
        return False


def port_scanner(ip, port):
    nmscan = nmap.PortScanner()
    nmscan.scan(ip, str(port))
    response = sr1(
        IP(dst=ip) / TCP(dport=int(port), flags="S"), timeout=1, verbose=False
    )
    if response and response.haslayer(TCP):
        if response[TCP].flags == "SA":
            if nmscan[ip]["tcp"][int(port)]["name"]:
                print(
                    "{}/tcp\t Open\t   {}".format(
                        port, nmscan[ip]["tcp"][int(port)]["name"]
                    )
                )
            else:
                print("{}/tcp\t Open\t   Unknown".format(port))
        if response[TCP].flags == "RA":
            if nmscan[ip]["tcp"][int(port)]["name"]:
                print(
                    "\r{}/tcp\t Closed\t   {}".format(
                        port, nmscan[ip]["tcp"][int(port)]["name"]
                    )
                )
    else:
        print("[-] TCP layer not found in the answered packet")


if __name__ == "__main__":
    try:
        args = get_args()
        ip_list = []
        port_list = []
        if "/" in args.target:
            if not args.target.endswith("/24"):
                raise ValueError(
                    "[-] Invalid subnet mask. only /24 or single ip is supported"
                )
        args.target = socket.gethostbyname(args.target)
        try:
            subnet = ipaddress.ip_network(args.target, strict=False)
            for i in subnet:
                ip_list.append(str(i))
        except ValueError:
            ip_list.append(args.target)

        if "-" in args.port:
            start_port, end_port = map(int, args.port.split("-"))
            for p in range(start_port, end_port + 1):
                port_list.append(p)
        elif "," in args.port:
            port_list = args.port.split(",")
        else:
            port_list.append(args.port)
        try:
            for ip in ip_list:
                result = ip_scanner(ip)
                if result:
                    print("--------------------")
                    print("PORT\t STATUS\t   SERVICE")
                    print("----------------------------------")
                    for port in port_list:
                        port_scanner(ip, str(port))
        except Exception as e:
            print("[-] Error : ", e)
    except ValueError:
        pass
    except Exception as e:
        print("[-] Error : ", e)
        pass
    except KeyboardInterrupt:
        pass
