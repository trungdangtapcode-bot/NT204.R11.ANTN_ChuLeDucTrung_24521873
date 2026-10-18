from scapy.all import IP, TCP, UDP, DNS, DNSQR, DNSRR, wrpcap, Raw

def generate_app_pcaps():
    # TC04: HTTP GET
    http_get = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    pkt4 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="PA") / Raw(load=http_get)
    wrpcap("tc04_http_get.pcap", [pkt4])

    # TC05: HTTP POST
    http_post = b"POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nuser=admin&pass=123"
    pkt5 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="PA") / Raw(load=http_post)
    wrpcap("tc05_http_post.pcap", [pkt5])

    # TC06: HTTP Response
    http_resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: nginx\r\n\r\n<html>Hi</html>"
    pkt6 = IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=1234, flags="PA") / Raw(load=http_resp)
    wrpcap("tc06_http_response.pcap", [pkt6])

    # TC07: DNS Query
    dns_query = DNS(rd=1, qd=DNSQR(qname="google.com", qtype=1))
    pkt7 = IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=1234, dport=53) / dns_query
    wrpcap("tc07_dns_query.pcap", [pkt7])

    # TC08: DNS Response
    dns_resp = DNS(qr=1, aa=1, rd=1, qd=DNSQR(qname="google.com", qtype=1), an=DNSRR(rrname="google.com", type=1, rdata="142.250.190.46"))
    pkt8 = IP(src="8.8.8.8", dst="10.0.0.1") / UDP(sport=53, dport=1234) / dns_resp
    wrpcap("tc08_dns_response.pcap", [pkt8])

    # TC09: SMTP Command
    smtp_cmd = b"EHLO mail.example.com\r\n"
    pkt9 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=25, flags="PA") / Raw(load=smtp_cmd)
    wrpcap("tc09_smtp_command.pcap", [pkt9])

    # TC10: SMTP Response
    smtp_resp = b"250-mail.example.com Hello\r\n250-SIZE 10485760\r\n250 AUTH LOGIN PLAIN\r\n"
    pkt10 = IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=25, dport=1234, flags="PA") / Raw(load=smtp_resp)
    wrpcap("tc10_smtp_response.pcap", [pkt10])

    # TC11: Unknown Protocol (No crash)
    unknown = b"SOMERANDOMPROTOCOL DATA"
    pkt11 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=9999, flags="PA") / Raw(load=unknown)
    wrpcap("tc11_unknown.pcap", [pkt11])

    # TC12: Malformed Packet (No crash)
    malformed = IP(src="10.0.0.1", dst="10.0.0.2") / b"JUNK_DATA_WITHOUT_TRANSPORT_HEADER"
    wrpcap("tc12_malformed.pcap", [malformed])

if __name__ == "__main__":
    generate_app_pcaps()
