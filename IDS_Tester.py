import sys
from argparse import ArgumentParser
import socket
import struct


class ICMP_packet():
    def __init__(self):
        self.type=8 # 0=Echo-Reply 8=Echo-Request
        self.code=0
        self.id=1
        self.sequence=1
        self.data=b''
        self.ip_version=4
        self.ip='93.184.216.34' # www.example.com
        self._header=b''
        self._id=0
        self._sequence=0

    def set_data_from_string(self,text):
        self.data=text.encode('utf-8')

    @property
    def id(self):
        return socket.htons(self._id)

    @id.setter
    def id(self,intValue):
        self._id=socket.ntohs(intValue)

    @property
    def sequence(self):
        return socket.htons(self._sequence)

    @sequence.setter
    def sequence(self,intValue):
        self._sequence=socket.ntohs(intValue)

    @property
    def header(self):
        if self.ip_version==4:
            return self._header_IPv4()
        # ONLY IPv4 IS CURRENTLY SUPPORTED
        return b''

    def _header_IPv4(self):
        # Return the raw data with an updated checksum
        raw = struct.pack('bbHHh', self.type,self.code,0,self._id,self._sequence,)
        checksum=self._checksum_IPv4(raw+self.data)
        raw = struct.pack('bbHHh',self.type,self.code,checksum,self._id,self._sequence,)
        return raw
        
    def _checksum_IPv4(self,message=b''):
        # Calculates the checksum required within an ICMP packet

        if len(message) % 2 == 1: message+=b'\x00'
        sum = 0

        for i in range(0, len(message), 2):
            byte1 = message[i]
            byte2 = message[i+1]
            sum = sum + (byte1+(byte2 << 8))
        
        sum+=(sum >> 16)
        sum = ~sum & 0xffff

        return sum

    def send_echo_reply(self):
        result=False
        if self.ip_version==4: 
            result=self._send_echo_reply_IPv4()
        else:
            print("[!] Error: Only IPv4 is currently supported.\n")
        return result

    def _send_echo_reply_IPv4(self):
        ICMP_code = socket.getprotobyname('icmp')
        
        try:
            ICMP_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_code)
        except socket.error as e:
            print(f"[!] Error: Socket error - Error {e.errno}\n")
            return False

        packet_remaining = self.header+self.data
        
        while packet_remaining:
            packet_sent = ICMP_socket.sendto(self.header+self.data, (self.ip, 1)) # 1 = arbitrary dummy port
            packet_remaining=packet_remaining[packet_sent:]
        ICMP_socket.close()
        
        return True
        

def main(args):
    packet=ICMP_packet()
    packet.set_data_from_string(args.text)
    packet.ip=args.ip
    packet.ip_version=args.ip_version
    packet.id=args.id
    packet.sequence=args.sequence
    packet.type=args.type
    packet.code=args.code
    print()
    print("[i] Parameters:")
    print(f" Header: {packet.header}")
    print(f" Data: {packet.data}")
    print(f" IP: {packet.ip}")
    print(f" Type: {packet.type}")
    print(f" ID: {packet.id}")
    print(f" Sequence: {packet.sequence}")
    print(f" Code: {packet.code}")
    result=packet.send_echo_reply()
    print(f"[i] Successfully sent: {result}\n")




if __name__ == "__main__":
    parser=ArgumentParser(prog="IDS Tester",description="Sends data within ICMP Echo-Response packets to test for IDS detection.", epilog="For educational purposes only. The author accepts no liability for its use.\nExample usage to send echo-response ICMP packet to www.example.com: python3 IDS_Tester.py --ip 93.184.216.34 Example usage to monitor packet: tcpdump dst 93.184.216.34 -XX")
    parser.add_argument('--ip',type=str,default="93.184.216.34",help="The IP to ping (default is www.example.com: 93.184.216.34)")
    parser.add_argument('--ip_version',type=int,default=4,help="Only IP version 4 is currently supported (default: 4)")
    parser.add_argument('--text',type=str,default="Test data",help="The string to include within the ICMP packet (default: \"Test data\")")
    parser.add_argument('--id',type=int,default=1,help="The identifying number of the packet (default: 1)")
    parser.add_argument('--sequence',type=int,default=1,help="The sequence number of the packet (default: 1)")
    parser.add_argument('--type',type=int,default=0,help="The type of ICMP packet. 0 is Echo-Response. 8 is Echo-Request (default: 0)")
    parser.add_argument('--code',type=int,default=0,help="The code of ICMP packet (default: 0)")
    
    args=parser.parse_args()
    main(args)
    sys.exit()