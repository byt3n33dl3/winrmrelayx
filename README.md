<div align="center">
<h1>winrmrelayx</h1>

Authentication opener with NTLM and Kerberos support for Winrm and Wmi. 
<p></div>

<p align="center">
  <a href="/local/src/winrm_usage.md">Usage</a> •
  <a href="/local/src/writeups.md">Exec</a> •
  <a href="/local/src/install.md">Install</a> •
  <a href="/local/src/adversarial_help.md">C2</a>
</p>

## Overview

Winrm and Wmi session opener with NTLM and Kerberos authentication support. This are Impacket based WinRM client with support for NTLM and Kerberos authentication over HTTP and HTTPs in the spirit of other impacket Exec kit. 

You can run a single command with -X `whoami /all`, or use the "shell" mode to issue multiple commands. It depends on impacket, requests, and optionally prompt_toolkit python packages. If prompt_toolkit is not installed on your system, it defaults to the built-in readline module.

<a href="https://github.com/byt3n33dl3/winrmrelayx"><p align="left">
<img src="/local/src/img/demon.png" width="240px">
</p></a>

![Python3](https://img.shields.io/badge/language-python3-blue.svg)<br>
![Nim](https://img.shields.io/badge/language-nim-yellow.svg)

> [!IMPORTANT]
(Experimental) evil_winrmrelayx.py adds a custom shell to replicate some of the features of evil-winrm like `AMSI bypasses` ability to download and upload files, run scripts/.NET executables from remote HTTP, etc. And help with Nim kit for post-exploitation and `C2 agent implant mode enable`.

<a href="https://github.com/byt3n33dl3/winrmrelayx"><p align="left">
<img src="/local/src/img/sx.jpg" width="100px">
</p></a>

## CONTACT

For more, come to my collections of write-ups for real-world use cases and write-ups [here](https://byt3n33dl3.substack.com), if there's any security concern, please contact me at <byt3n33dl3@pm.me>