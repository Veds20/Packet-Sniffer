import asyncio, json, socket, struct, threading, time
from fastapi import FastAPI, WebSocket
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

clients=[]; capturing=False; proto_filter="ALL"; max_packets=200; _count=0

def parse_pkt(data:bytes):
    # detect link-layer IPv4/IPv6 (ethertype at offset 12) else assume IP start
    ip_off=0
    if len(data)>=14:
        et=int.from_bytes(data[12:14],'big')
        if et in (0x0800,0x86DD): ip_off=14
    if len(data)<ip_off+1: return None
    ver=data[ip_off]>>4
    if ver==4 and len(data)>=ip_off+20:
        h=struct.unpack('!BBHHHBBH4s4s', data[ip_off:ip_off+20])
        ihl=(h[0]&0x0F)*4; proto=h[6]; src=socket.inet_ntoa(h[8]); dst=socket.inet_ntoa(h[9]); total=h[2]
        size=total or (len(data)-ip_off); payload=data[ip_off+ihl:ip_off+ihl+32]
    elif ver==6 and len(data)>=ip_off+40:
        proto=data[ip_off+6]; src=':'.join(f"{data[ip_off+8+i]:02x}{data[ip_off+9+i]:02x}" for i in range(0,16,2))
        dst=':'.join(f"{data[ip_off+24+i]:02x}{data[ip_off+25+i]:02x}" for i in range(0,16,2))
        payload=data[ip_off+40:ip_off+72]; size=40+int.from_bytes(data[ip_off+4:ip_off+6],'big')
    else:
        return None
    p="OTHER"
    if proto==6: p="TCP"
    if proto==17: p="UDP"
    if proto==1: p="ICMP"
    return {"ip_version":f"IPv{ver}","protocol":p,"src":src,"dst":dst,"payload":payload.hex(),"size":int(size)}

def broadcast(obj:dict):
    text=json.dumps(obj)
    for ws in clients.copy():
        try: asyncio.run(ws.send_text(text))
        except: 
            try: clients.remove(ws)
            except: pass

def sniff(iface):
    global capturing,_count,proto_filter,max_packets
    _count=0
    s=None
    try:
        s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3)); s.bind((iface,0))
    except Exception:
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP); s.bind(("0.0.0.0",0)); s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
        except Exception as e:
            broadcast({"status":"error","msg":str(e)}); capturing=False; return
    broadcast({"status":"started"})
    while capturing:
        try:
            data,_=s.recvfrom(65535)
        except Exception:
            break
        p=parse_pkt(data)
        if not p: continue
        if proto_filter!="ALL" and p["protocol"]!=proto_filter: continue
        _count+=1
        msg={"type":"packet","pkt":{"index":_count,"timestamp":time.time(),"ip_version":p["ip_version"],
             "protocol":p["protocol"],"src":p["src"],"dst":p["dst"],"size":p["size"],"payload":p["payload"]}}
        broadcast(msg)
        if max_packets and _count>=max_packets:
            capturing=False
            broadcast({"status":"stopped","count":_count,"reason":"max_reached"})
            break
    try: s.close()
    except: pass
    if not capturing: broadcast({"status":"stopped","count":_count})

@app.get("/")
async def index(): return FileResponse("static/index.html")

@app.websocket("/ws")
async def ws(ws:WebSocket):
    await ws.accept(); clients.append(ws)
    try:
        while True:
            d=await ws.receive_text(); cmd=json.loads(d)
            action=cmd.get("action","")
            global capturing,proto_filter,max_packets
            if action=="start":
                proto_filter=cmd.get("filter","ALL"); 
                try: max_packets=int(cmd.get("max",200))
                except: max_packets=200
                iface=cmd.get("iface","eth0")
                if not capturing:
                    capturing=True
                    threading.Thread(target=sniff,args=(iface,),daemon=True).start()
                else:
                    await ws.send_text(json.dumps({"status":"already_running"}))
            elif action=="stop":
                capturing=False; await ws.send_text(json.dumps({"status":"stopping"}))
            elif action=="ping":
                await ws.send_text(json.dumps({"status":"pong"}))
    except Exception:
        pass
    finally:
        try: clients.remove(ws)
        except: pass
