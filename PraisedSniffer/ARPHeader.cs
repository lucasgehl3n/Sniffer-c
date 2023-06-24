using PacketDotNet;
using System;
using System.Net.NetworkInformation;
using System.Net;
using System.IO;

namespace PraisedSniffer
{
    public class ARPHeader
    {
        private ARPPacket _arpPacket;

        public ARPHeader(ARPPacket arpPacket)
        {
            _arpPacket = arpPacket;
        }

        public int HardwareAddressLength
        {
            get { return _arpPacket.HardwareAddressLength; }
        }

        public int ProtocolAddressLength
        {
            get { return _arpPacket.ProtocolAddressLength; }
        }

        public ARPOperation Operation
        {
            get { return _arpPacket.Operation; }
        }

        public PhysicalAddress SenderHardwareAddress
        {
            get { return _arpPacket.SenderHardwareAddress; }
        }

        public IPAddress SenderProtocolAddress
        {
            get { return _arpPacket.SenderProtocolAddress; }
        }

        public PhysicalAddress TargetHardwareAddress
        {
            get { return _arpPacket.TargetHardwareAddress; }
        }

        public IPAddress TargetProtocolAddress
        {
            get { return _arpPacket.TargetProtocolAddress; }
        }
    }
}