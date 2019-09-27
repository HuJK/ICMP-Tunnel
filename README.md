# ICMP-Tunnel

ICMP tunnel implement by python3
AES-CTR encryption

# Usage

```bash
#Disable kernal reply ping echo requests
sudo echo "1" >  /proc/sys/net/ipv4/icmp_echo_ignore_all
#Run server
sudo ./tunnel_server.py 10.99.8.1/24 Password AES-CTR_password 1000
```

on client
```bash
./tunnel_client.py example.com password AES-CTR_password 1000
```
