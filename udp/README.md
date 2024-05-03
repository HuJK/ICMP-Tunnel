# ICMP-Tunnel

ICMP tunnel implement by python3
AES-CTR encryption

# Usage

```bash
#Run server
sudo ./tunnel_server.py 127.0.0.1:51820 client_password AES-CTR_password 1450
```

on client
```bash
#Allow icmp packets
sudo echo "0 429496729" >  /proc/sys/net/ipv4/ping_group_range
#Run client
./tunnel_client.py example.com client_password AES-CTR_password 1450 base64_8byte_clientID 51820
```
