using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace PraisedSniffer
{
    public class IPHeaderV6 : IIpHeader
    {
        private uint _versionTrafficClassAndFlowLabel;

        private ushort _payloadLength;

        private byte _nextHeader;
        private byte _hopLimit;

        private byte[] _sourceAddress = new byte[16];
        private byte[] _destinationAddress = new byte[16];

        public IPHeaderV6(BinaryReader binaryReader, IP2Location.Component ip2l)
        {
            _versionTrafficClassAndFlowLabel = (uint)IPAddress.NetworkToHostOrder(binaryReader.ReadInt32());

            _payloadLength = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            _nextHeader = binaryReader.ReadByte();

            _hopLimit = binaryReader.ReadByte();

            for (int i = 0; i < 16; i++)
            {
                _sourceAddress[i] = binaryReader.ReadByte();
            }

            SourceAddress = new ExtendedIpAddress(_sourceAddress, ip2l);
            SourceAddress.ToString();

            for (int i = 0; i < 16; i++)
            {
                _destinationAddress[i] = binaryReader.ReadByte();
            }

            DestinationAddress = new ExtendedIpAddress(_destinationAddress, ip2l);
        }

        public string Version
        {
            get
            {
                return "IP v6";
            }
        }

        public string TrafficClass
        {
            get
            {
                uint trafficClass = _versionTrafficClassAndFlowLabel << 4;
                trafficClass >>= 24;

                if (trafficClass == 0)
                {
                    return "Nenhum tráfego específico";
                }
                else if (trafficClass == 1)
                {
                    return "Dados de segundo plano";
                }
                else if (trafficClass == 2)
                {
                    return "Tráfego de dados não atendido";
                }
                else if (trafficClass == 3)
                {
                    return "Reservado";
                }
                else if (trafficClass == 4)
                {
                    return "Tráfego de dados pesado atendido";
                }
                else if (trafficClass == 5)
                {
                    return "Reservado";
                }
                else if (trafficClass == 6)
                {
                    return "Tráfego interativo";
                }
                else if (trafficClass == 7)
                {
                    return "Tráfego de controle";
                }
                else
                {
                    return "Desconhecido";
                }
            }
        }

        public string FlowLabel
        {
            get
            {
                uint flowLabel = _versionTrafficClassAndFlowLabel << 12;
                flowLabel >>= 12;

                return string.Format("0x{0:x2}", flowLabel);
            }
        }

        public string PayloadLength
        {
            get
            {
                return _payloadLength.ToString();
            }
        }

        public string NextHeader
        {
            get
            {
                switch (_nextHeader)
                {
                    case 6:
                        return "TCP";
                    case 17:
                        return "UDP";
                    case 41:
                        return "Encapsulamento de Cabeçalho IPv6";
                    case 43:
                        return "Cabeçalho de Roteamento";
                    case 44:
                        return "Cabeçalho de Fragmentação";
                    case 50:
                        return "Carga de Segurança de Encapsulamento";
                    case 51:
                        return "Cabeçalho de Autenticação";
                    case 58:
                        return "ICMPv6";
                    case 59:
                        return "Nenhum";
                    case 60:
                        return "Cabeçalho de Opções de Destino";
                    default:
                        return "Desconhecido";
                }
            }
        }

        public string HopLimit
        {
            get
            {
                return _hopLimit.ToString();
            }
        }

        public ExtendedIpAddress SourceAddress { get; }

        public ExtendedIpAddress DestinationAddress { get; }
    }
}
