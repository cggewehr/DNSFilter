import ctypes
from datetime import datetime
import os
import platform as plat
import pydivert
from dns.name import *
from scapy.all import *


def DNSFilter(args):

    # Check if Windows
    if plat.system() != "Windows":
        raise ValueError("Only Windows is currently supported. Your OS is: " + str(plat.system()))
        
    # Check if running as admin
    if not ctypes.windll.shell32.IsUserAnAdmin():
        
        while True:
            print("Warning: You are not running this script as admin. This may cause some problems with the WinDivert driver. Proceed? (Y/N)")
            
            ipt = input()
            
            if ipt == "Y" or ipt == "y":
                break
                
            elif ipt == "N" or ipt == "n":
                exit(0)

    # Reads blacklist file line-by-line and put it into a list of dnspython domain type
    try:
        with open(args.blacklist, "r") as blacklistFile:
            blacklistedDomains = [from_text(line.rstrip()) for line in blacklistFile.readlines()]

    except FileNotFoundError:
        raise ValueError("Blacklist file <" + args.blacklist + "> cannot be found")

    except OSError:
        raise ValueError("Error opening blacklist file <" + args.blacklist + ">")

    # Open log file
    try:
        if args.log is not None:
            logFile = open(args.log, "w")

    except OSError:
        raise ValueError("Error opening log file <" + args.log + ">")
        
    # Prints out domains to be blocked if verbose
    if args.log:
        logFile.write("Read blacklist file <" + args.blacklist + ">, containing domains:\n")
        for blacklistedDomain in blacklistedDomains:
            logFile.write("\t" + str(blacklistedDomain) + "\n")
    if args.verbose:
        print("Read blacklist file <" + args.blacklist + ">, containing domains:")
        for blacklistedDomain in blacklistedDomains:
            print("\t" + str(blacklistedDomain))
       
       
    # Flushes DNS cache before execution (so that there are no blacklisted domains in cache)
    if args.flush:
    
        if args.log:
            logFile.write("Flushing DNS cache @ " + str(datetime.now()) + "\n")
        if args.verbose:
            print("Flushing DNS cache @ " + str(datetime.now()))
    
        os.system("ipconfig /flushdns")
    
    # Open PyDivert handle @ UDP DNS port (53)
    pyDivertFilter = pydivert.WinDivert("udp.SrcPort == 53 or udp.DstPort == 53")
    pyDivertFilter.open()
    
    if args.log:
        logFile.write("Opened PyDivert handle for UDP port 53 @ " + str(datetime.now()) + "\n")
    if args.verbose:
        print("Opened PyDivert handle for UDP port 53 @ " + str(datetime.now()))
        
    # Init byte counters and latency running averages
    avgLatencyQueries = datetime.now() - datetime.now()
    queriesAmount = 0
    queriesBytes = 0
    avgLatencyReplies = datetime.now() - datetime.now()
    repliesAmount = 0
    repliesBytes = 0
    avgLatencyLetThrough = datetime.now() - datetime.now()
    letThroughAmount = 0
    letThroughBytes = 0

    # Intercept packets @ UDP port 53 and compare query domain to blacklisted domains
    try:
    
        print("Now intercepting packets @ UDP port 53. Press CTRL + C to exit")

        while(True):
            
            # Wait for new packet in filter
            pyDivertPacket = pyDivertFilter.recv()
            receiveTimestamp = datetime.now()
            
            # DEBUG: Prints out PyDivert intercepted packet
            #print(pyDivertPacket)
            
            if args.log:
                logFile.write("Packet intercepted @ " + str(datetime.now()) + "\n")
            if args.verbose:
                print("Packet intercepted @ " + str(datetime.now()))
            
            # Convert PyDivert packet to Scapy packet
            if pyDivertPacket.ipv6 is None:
                scapyPacket = IP(pyDivertPacket.raw.tobytes())
                IPv6Packet = False
            else:
                scapyPacket = IPv6(pyDivertPacket.raw.tobytes())
                IPv6Packet = True
                
            # DEBUG: Prints out Scapy packet
            #print(scapyPacket.summary())
            
            # Get queried domain from Scapy packet
            if not DNS in scapyPacket:
            
                if args.log:
                    logFile.write("Non-DNS packet let through @ " + str(datetime.now()) + "\n")
                if args.verbose:
                    print("Non-DNS packet let through @ " + str(datetime.now()))
                    
                pyDivertFilter.send(pyDivertPacket)
                continue
            
            # DNS Query
            elif DNSQR in scapyPacket:  
                query = True
                #queryDomain = dnslib.name.from_text(scapyPacket[DNSQR].qname)
                queryDomain = from_text(scapyPacket[DNSQR].qname)
                
            # DNS Reply
            elif DNSRR in scapyPacket:  
                query = False
                #queryDomain = dnslib.name.from_text(scapyPacket[DNSRR].qname)
                queryDomain = from_text(scapyPacket[DNSRR].qname)
                
            # DNS packet but not DNSQR or DNSRR
            else:  
            
                # DEBUG
                print("Something terrible has happened")
                exit(1)
            
            # DEBUG
            #print("Query domain: " + str(queryDomain))
            
            # Blocks query if domain is in blacklist
            #if str(queryDomain) in blacklistedDomains:
            #if reduce(lambda a, b: queryDomain.is_subdomain(a) or queryDomain.is_subdomain(b), blacklistedDomains):
            if len(list(filter(queryDomain.is_subdomain, blacklistedDomains))) != 0:
                
                # Blocks outgoing query
                if query:
                    
                    # Make DNS reply packet signaling domain not found (RCODE = 3, NXDOMAIN) (https://www.cs.dartmouth.edu/~sergey/netreads/local/reliable-dns-spoofing-with-python-scapy-nfqueue.html#selection-821.1-1157.2)
                    if IPv6Packet:
                    
                        scapyPacket = IPv6(dst = scapyPacket[IPv6].src, src = scapyPacket[IPv6].dst)/\
                                  UDP(dport = scapyPacket[UDP].sport, sport = scapyPacket[UDP].dport)/\
                                  DNS(id = scapyPacket[DNS].id, qd = scapyPacket[DNS].qd, aa = 1, qr=1, rcode = 3,\
                                  an=DNSRR(rrname=scapyPacket[DNS].qd.qname, ttl=1000))
                                  
                    else:
                    
                        scapyPacket = IP(dst = scapyPacket[IP].src, src = scapyPacket[IP].dst)/\
                                      UDP(dport = scapyPacket[UDP].sport, sport = scapyPacket[UDP].dport)/\
                                      DNS(id = scapyPacket[DNS].id, qd = scapyPacket[DNS].qd, aa = 1, qr=1, rcode = 3,\
                                      an=DNSRR(rrname=scapyPacket[DNS].qd.qname, ttl=1000))
                                  
                    pyDivertPacket = pydivert.Packet(raw(scapyPacket), pyDivertPacket.interface, 1)
                    
                    #DEBUG
                    #print(pyDivertPacket)
                    
                    # Send packet thorugh PyDivert handle
                    pyDivertFilter.send(pyDivertPacket)
                    
                    # Compute latency & avg latency
                    sendTimestamp = datetime.now()
                    latency = sendTimestamp - receiveTimestamp
                    
                    # https://en.wikipedia.org/wiki/Moving_average
                    avgLatencyQueries = avgLatencyQueries + ((latency - avgLatencyQueries)/ (queriesAmount + 1))
                    queriesAmount += 1
                    
                    queriesBytes += len(scapyPacket)
                                  
                    if args.log:
                        logFile.write("Blocked outgoing query to blacklisted domain <" + str(queryDomain) + "> @ " + str(sendTimestamp) + "\n")
                        logFile.write("Processing latency: " + str(latency) + "\n\n")
                    if args.verbose:
                        print("Blocked outgoing query to blacklisted domain <" + str(queryDomain) + "> @ " + str(sendTimestamp))
                        print("Processing latency: " + str(latency) + "\n")
                        
                # Spoofs incoming reply
                else:
                
                    # Make DNS reply packet signaling domain not found (RCODE = 3)
                    if IPv6Packet:
                    
                        scapyPacket = IPv6(dst = scapyPacket[IPv6].dst, src = scapyPacket[IPv6].src)/\
                                      UDP(dport = scapyPacket[UDP].dport, sport = scapyPacket[UDP].sport)/\
                                      DNS(id = scapyPacket[DNS].id, qd = scapyPacket[DNS].qd, aa = 1, qr=1, rcode = 3,\
                                      an=DNSRR(rrname=scapyPacket[DNS].qd.qname, ttl=1000))
                                      
                    else:
                    
                        scapyPacket = IP(dst = scapyPacket[IP].dst, src = scapyPacket[IP].src)/\
                                      UDP(dport = scapyPacket[UDP].dport, sport = scapyPacket[UDP].sport)/\
                                      DNS(id = scapyPacket[DNS].id, qd = scapyPacket[DNS].qd, aa = 1, qr=1, rcode = 3,\
                                      an=DNSRR(rrname=scapyPacket[DNS].qd.qname, ttl=1000))
                    
                    pyDivertPacket = pydivert.Packet(raw(scapyPacket), pyDivertPacket.interface, 1)
                    
                    #DEBUG
                    #print(pyDivertPacket)
                    
                    # Send packet thorugh PyDivert handle
                    pyDivertFilter.send(pyDivertPacket)
                    
                    # Compute latency & avg latency
                    sendTimestamp = datetime.now()
                    latency = sendTimestamp - receiveTimestamp
                    
                    # https://en.wikipedia.org/wiki/Moving_average
                    avgLatencyReplies = avgLatencyReplies + ((latency - avgLatencyReplies)/ (repliesAmount + 1))
                    repliesAmount += 1
                    
                    repliesBytes += len(scapyPacket)
                    
                    if args.log:
                        logFile.write("Blocked incoming reply to blacklisted domain <" + str(queryDomain) + "> @ " + str(sendTimestamp) + "\n")
                        logFile.write("Processing latency: " + str(latency) + "\n\n")
                    if args.verbose:
                        print("Blocked incoming reply to blacklisted domain <" + str(queryDomain) + "> @ " + str(sendTimestamp))
                        print("Processing latency: " + str(latency) + "\n")
                    
            # Let query through
            else:        
            
                # Send packet thorugh PyDivert handle
                pyDivertFilter.send(pyDivertPacket)
                
                # Compute latency & avg latency
                sendTimestamp = datetime.now()
                latency = sendTimestamp - receiveTimestamp
                    
                # https://en.wikipedia.org/wiki/Moving_average
                avgLatencyLetThrough = avgLatencyLetThrough + ((latency - avgLatencyLetThrough)/ (letThroughAmount + 1))
                letThroughAmount += 1
                
                letThroughBytes += pyDivertPacket.ipv6.packet_len if IPv6Packet else pyDivertPacket.ipv4.packet_len
                
                if args.log:
                    logFile.write("Let through query to non-blacklisted domain <" + str(queryDomain) +  "> @ " + str(sendTimestamp) + "\n")
                    logFile.write("Processing latency: " + str(sendTimestamp - receiveTimestamp) + "\n\n")
                if args.verbose:
                    print("Let through query to non-blacklisted domain <" + str(queryDomain) +  "> @ " + str(sendTimestamp))
                    print("Processing latency: " + str(latency) + "\n")

    # Tidy up and exit when CTRL + C interrupt
    except KeyboardInterrupt:

        # Close PyDivert handle
        pyDivertFilter.close()
        if args.log:
            logFile.write("Closing PyDivert handle @ " + str(datetime.now()) + "\n")
        if args.verbose:
            print("Closing PyDivert handle @ " + str(datetime.now()))
        
        # Flush DNS cache, so that spoofed replies are invalidated
        if args.log:
            logFile.write("Flushing DNS cache @ " + str(datetime.now()) + "\n")
        if args.verbose:
            print("Flushing DNS cache @ " + str(datetime.now()))
            
        os.system("ipconfig /flushdns")
        
        # Final statistics for run
        if args.log:
            logFile.write("Total packets handled: " + str(queriesAmount + repliesAmount + letThroughAmount) + "\n")
            logFile.write("Total bytes handled: " + str(queriesBytes + repliesBytes + letThroughBytes) + "\n")
            logFile.write("Blocked queries amount: " + str(queriesAmount) + "\n")
            logFile.write("Blocked queries bytes: " + str(queriesBytes) + "\n")
            logFile.write("Blocked queries average latency: " + str(avgLatencyQueries) + "\n")
            logFile.write("Blocked replies amount: " + str(repliesAmount) + "\n")
            logFile.write("Blocked replies bytes: " + str(repliesAmount) + "\n")
            logFile.write("Blocked replies average latency: " + str(avgLatencyReplies) + "\n")
            logFile.write("Let through packets: " + str(letThroughAmount) + "\n")
            logFile.write("Let through bytes: " + str(letThroughBytes) + "\n")
            logFile.write("Let through average latency: " + str(avgLatencyLetThrough) + "\n")
        if args.verbose:
            print("Total packets handled: " + str(queriesAmount + repliesAmount + letThroughAmount))
            print("Total bytes handled: " + str(queriesBytes + repliesBytes + letThroughBytes))
            print("Blocked queries amount: " + str(queriesAmount))
            print("Blocked queries bytes: " + str(queriesBytes))
            print("Blocked queries average latency: " + str(avgLatencyQueries))
            print("Blocked replies amount: " + str(repliesAmount))
            print("Blocked replies bytes: " + str(repliesAmount))
            print("Blocked replies average latency: " + str(avgLatencyReplies))
            print("Let through packets: " + str(letThroughAmount))
            print("Let through bytes: " + str(letThroughBytes))
            print("Let through average latency: " + str(avgLatencyLetThrough))
        
        if args.log:
            logFile.write("Exiting filter @ " + str(datetime.now()) + "\n")
        if args.verbose:
            print("Exiting filter @ " + str(datetime.now()))
            
        if args.log:
            logFile.close()
            
        return
            
            
# If run as script, get args from shell and call DNSFilter()
if __name__ == "__main__":

    import argparse
    
    parser = argparse.ArgumentParser()
    
    parser.add_argument("-b", "--blacklist", help = "File containing blacklisted domains", required = True)
    parser.add_argument("-l", "--log", help = "File containing relevant events in script execution")
    parser.add_argument("-v", "--verbose", help = "Print out in console revelant events in script execution", action = "store_true")
    parser.add_argument("-f", "--flush", help = "Flush DNS cache before script execution (Cache is always flushed on exit)", action = "store_true")
    
    args = parser.parse_args()
    
    DNSFilter(args)
