from scapy.all import *  

mac_list=[]
def CallBack(packet):
    global mac_list
    if packet.haslayer('ARP'):
        #如果mac地址不在list[]中，则添加到list[]中，并打印
        if packet['ARP'].hwsrc not in mac_list:
            mac_list.append(packet['ARP'].hwsrc)
            print ("the IP is:"+packet['ARP'].pdst)
            print ("the MAC is:"+packet['ARP'].hwsrc+"\r\n")
    time.sleep(1)

filter="arp"

try:
    sniff(filter=filter, prn=CallBack, iface='Ethernet', timeout=30)
except KeyboardInterrupt:
    #捕获Ctrl+C，退出程序
    print ("exit")