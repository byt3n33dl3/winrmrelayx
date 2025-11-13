## Usage in Details

Same as impacket-based execution, the format are including Username, credentials (Hashes or Passwd), followed by the DC domain and IP addresses. 

`[[domain/]username[:password]@]<target>`

_NTLM scenario:_

```sh
┌──(kali㉿kali)-[~]
└─$ winrmexec.py 'LAB.corp/Administrator:P#ssw0rd123@DC02.LAB.corp'

┌──(kali㉿kali)-[~]
└─$ winrmexec.py 'username:password@DC02.LAB.corp'

┌──(kali㉿kali)-[~]
└─$ winrmexec.py -hashes 'LM:NT' 'username@DC02.LAB.corp'

┌──(kali㉿kali)-[~]
└─$ winrmexec.py -hashes :NT 'username@DC02.LAB.corp'
```

Other than this command, you can also try with no password and it will automatically ask for password: 
```sh
┌──(kali㉿kali)-[~]
└─$ winrmexec.py username@DC02.LAB.corp
Password:
```

Other command specification are including:
```sh
-target-ip
-ssl
-ssl -port 8888
-url [specified URL endpoint]
```

_Kerberos scenario:_

```sh
┌──(kali㉿kali)-[~]
└─$ winrmexec.py -k 'LAB.corp/Administrator:P#ssw0rd123@DC02.LAB.corp'

┌──(kali㉿kali)-[~]
└─$ winrmexec.py -k 'username:password@DC02.LAB.corp'

┌──(kali㉿kali)-[~]
└─$ winrmexec.py -k -hashes LM:NT 'username@DC02.LAB.corp'

┌──(kali㉿kali)-[~]
└─$ winrmexec.py -k -aesKey 'AESHEX' -hashes :NT 'username@DC02.LAB.corp'
```

Other command specification are including:
```sh
-k
-spn 
-no-pass
-dc-ip
```

Note: If you have a TGS for SPN other than HTTP (for example CIFS) it still works (at least from what i tried). If you have a TGT, then it will request TGS for HTTP/target@domain (or your custom -spn). If -dc-ip is not specified then -dc-ip=domain. For -url / -port / -ssl same rules apply as for NTLM.

_ADCS and Certificate scenario:_

```sh
┌──(kali㉿kali)-[~]
└─$ winrmexec.py -cert-pem 'administrator.pem' -cert-key 'administrator.key' DC02.LAB.corp
```

_Overall Commands:_

winrmexec.py

```sh
┌──(root㉿kali)-[/]
└─# python3 winrmexec.py -h                                                                                                              
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

usage: winrmexec.py [-h] [-ts] [-debug] [-dc-ip DC_IP] [-target-ip TARGET_IP] [-port PORT] [-ssl] [-url URL] [-spn SPN] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey HEXKEY] [-basic] [-cert-pem CERT_PEM] [-cert-key CERT_KEY]
                    [-credssp] [-X COMMAND] [-timeout SECONDS]
                    target

positional arguments:
  target                [[domain/]username[:password]@]<target>

options:
  -h, --help            show this help message and exit
  -ts                   adds timestamp to every logging output
  -debug                Turn DEBUG output ON
  -X COMMAND            Command to execute, if ommited it will spawn a janky interactive shell
  -timeout SECONDS      Timeout for requests to /wsman

connection:
  -dc-ip DC_IP          IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter
  -target-ip TARGET_IP  IP Address of the target machine. If ommited it will use whatever was specified as target. This is useful when target is the NetBIOSname and you cannot resolve it
  -port PORT            Destination port to connect to WinRM http server, default is 5985
  -ssl                  Use HTTPS
  -url URL              Exact WSMan endpoint, eg. http://host:port/custom_wsman. Otherwise it will be constructed as http(s)://target_ip:port/wsman

authentication:
  -spn SPN              Specify exactly the SPN to request for TGS
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME)based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line
  -aesKey HEXKEY        AES key to use for Kerberos Authentication
  -basic                Use Basic auth
  -cert-pem CERT_PEM    Client certificate
  -cert-key CERT_KEY    Client certificate private key
  -credssp              Use CredSSP if enabled, works with NTLM and Kerberos but it needs plaintext password either way
```

evil_winrmrelayx.py

```sh
┌──(root㉿kali)-[/]
└─# python3 evil_winrmrelayx.py -h
usage: evil_winrmrelayx.py [-h] [-ts] [-debug] [-dc-ip DC_IP] [-target-ip TARGET_IP] [-port PORT] [-ssl] [-url URL] [-spn SPN] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey HEXKEY] [-basic] [-cert-pem CERT_PEM] [-cert-key CERT_KEY]
                         [-credssp] [-X COMMAND] [-timeout SECONDS]
                         target

positional arguments:
  target                [[domain/]username[:password]@]<target>

options:
  -h, --help            show this help message and exit
  -ts                   adds timestamp to every logging output
  -debug                Turn DEBUG output ON
  -X COMMAND            Command to execute, if ommited it will spawn a janky interactive shell
  -timeout SECONDS      Timeout for requests to /wsman

connection:
  -dc-ip DC_IP          IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter
  -target-ip TARGET_IP  IP Address of the target machine. If ommited it will use whatever was specified as target. This is useful when target is the NetBIOSname and you cannot resolve it
  -port PORT            Destination port to connect to WinRM http server, default is 5985
  -ssl                  Use HTTPS
  -url URL              Exact WSMan endpoint, eg. http://host:port/custom_wsman. Otherwise it will be constructed as http(s)://target_ip:port/wsman

authentication:
  -spn SPN              Specify exactly the SPN to request for TGS
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME)based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line
  -aesKey HEXKEY        AES key to use for Kerberos Authentication
  -basic                Use Basic auth
  -cert-pem CERT_PEM    Client certificate
  -cert-key CERT_KEY    Client certificate private key
  -credssp              Use CredSSP if enabled, works with NTLM and Kerberos but it needs plaintext password either way
```

## CONTACT

For more, come to my collections of write-ups for real-world use cases and write-ups [here](https://byt3n33dl3.substack.com), if there's any security concern, please contact me at <byt3n33dl3@pm.me>
