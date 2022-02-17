# -*- coding: utf-8 -*-

"""DataScienceSeg-Tarefa1.ipynb
Original file is located at
    https://colab.research.google.com/drive/1d2yNtFrSSXAdyGkcUxXMh2-hDvJ0ac2_#scrollTo=O18l6nRCkrbS

Aluno Artur Ricardo Bizon
Matricula 202100159073
Mestrado PPGInf
"""

from scapy.all import *

def get_number_of_packets_for_each_ip_protocol(sessionsDict):
  protocolsDict = {}
  for key in sessionsDict:
    protocol = key.split(" ")[0]
    nPacks = len(sessionsDict[key])
    if not protocol in protocolsDict:
      protocolsDict[protocol] = nPacks
    else:
      protocolsDict[protocol] += nPacks
  
  return protocolsDict

def create_readable_session_dict(sessions):
  sessionsDict = {}
  for session in sessions:
    sessionsDict[session] = []
    for packet in sessions[session]:
      sessionsDict[session].append(bytes(packet.payload).decode("ascii",
                                                                "backslashreplace"))
  return sessionsDict


def get_ip_packets(packets):
  return list(filter(lambda x: IP in x, packets))

def get_no_ip_packets(packets):
  return list(filter(lambda x: not IP in x, packets))


pcapFilePath = r"Dados\pacotes.pcap"
packetsData = rdpcap(pcapFilePath)

ipPackets = get_ip_packets(packetsData)
noIpPackets = get_no_ip_packets(packetsData)

sessions = packetsData.sessions()
sumDict = get_number_of_packets_for_each_ip_protocol(sessions)

mappedProtocols = list(sumDict)
nSessionDict = {"UDP":0, "TCP":0}
for session in sessions:
  if session.startswith("UDP"):
    nSessionDict["UDP"] += 1
  
  if session.startswith("TCP"):
    nSessionDict["TCP"] += 1

print("O arquivo possui {} pacotes no total \n".format(len(packetsData)))
print("O arquivo possui {} pacotes IP \n".format(len(ipPackets)))
print("O arquivo possui {} pacotes não IP \n".format(len(noIpPackets)))

for protocol in sumDict:
  print("O arquivo possui {} pacotes {} \n".format(sumDict[protocol], protocol))  

for key in nSessionDict:
  print("O arquivo possui {} sessoes {} \n".format(nSessionDict[key], key))

sessionsData = create_readable_session_dict(sessions)

# Para exibir a parte de conversao dos dados legiveis tirar os comentarios do codigo abaixo, deixei comentado para nao poluir tanto a saida no terminal
# for session in sessionsData:
#   print("============== Sessao {} ==================".format(session))
#   for packet in sessionsData[session]:
#     print(packet)
#     print()

