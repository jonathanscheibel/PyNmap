# PyNmap


## Descrição:
Script em python que recebe um (ou uma lista) de hosts por parâmetro, e realiza um port scan através de integração do python e nmap. O código é resiliente a travamentos do nmap, pois caso ele não retorne a resposta em até 1 minuto (ou tempo parametrizado), a ação é interrompida retornando o status de erro. O script está preparado para diferentes outputs.

### Algumas funcionalidades

* Informar um ou vários hosts
* Padrão de portas do nmap
* Diferentes tipos de outputs
* Configuração de parametrização do nmap
* Etc

## Utilização:

### Preparação do ambiente:

```
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```


### Exemplos de utilização:

> Utilização básica:

```
$ python pynmap.py -hosts 127.0.0.1

================================================================================
Host: 127.0.0.1 (localhost)	Status: up 
Porta: 22	Status: open	Nome: ssh	Produto: OpenSSH
Porta: 80	Status: open	Nome: http	Produto: Apache httpd
```

> Exemplo para lista de hosts:

```
$ python pynmap.py -hosts 127.0.0.1 192.168.0.1

================================================================================
Host: 127.0.0.1 (localhost)	Status: up 
Porta: 22	Status: open	Nome: ssh	Produto: OpenSSH
Porta: 80	Status: open	Nome: http	Produto: Apache httpd
================================================================================
Host: 192.168.0.1 ()	Status: up 
Porta: 22	Status: open	Nome: ssh	Produto: Dropbear sshd
Porta: 23	Status: open	Nome: telnet	Produto: 
Porta: 53	Status: open	Nome: domain	Produto: Unbound
Porta: 80	Status: open	Nome: http	Produto: 
```


> Exemplos para timeout modificados (padrão: um minuto):

```
$ python pynmap.py -hosts 127.0.0.1 --timeout 300

$ python pynmap.py -hosts 127.0.0.1 -t 600
```


> Exemplo para especificação de porta:

```
$ python pynmap.py -hosts 127.0.0.1 -p 22

$ python pynmap.py -hosts 127.0.0.1 -p 1-8080
```


> Exemplos para argumentos explícitos e/ou configurados:

```
$python pynmap.py -hosts 127.0.0.1 -arguments='-sV'

$ python pynmap.py -hosts 127.0.0.1 -arguments_conf NMAP_DEFAULT_ATTACK
```


> Exemplo para diferentes padrões (Padrão: console):

```
$ python pynmap.py -hosts 127.0.0.1 192.168.0.1 -t 600 -o console

================================================================================
Host: 192.168.0.1 ()	Status: up 
Porta: 22	Status: open	Nome: ssh	Produto: Dropbear sshd
Porta: 23	Status: open	Nome: telnet	Produto: 
Porta: 53	Status: open	Nome: domain	Produto: Unbound
Porta: 80	Status: open	Nome: http	Produto: 
```

```
$ python pynmap.py -hosts 127.0.0.1 -output xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.92 scan initiated Sat Apr  2 20:51:57 2022 as: nmap -oX - -p 1-1024 -v -sV -Pn 127.0.0.1 -->
<nmaprun scanner="nmap" args="nmap -oX - -p 1-1024 -v -sV -Pn 127.0.0.1" 
[...]
```

```
$ python pynmap.py -hosts 127.0.0.1 --output csv

host;hostname;hostname_type;protocol;port;name;state;product;extrainfo;reason;version;conf;cpe
127.0.0.1;localhost;PTR;tcp;22;ssh;open;OpenSSH;protocol 2.0;syn-ack;8.4p1 Debian 5;10;cpe:/o:linux:linux_kernel
127.0.0.1;localhost;PTR;tcp;80;http;open;Apache httpd;(Debian);syn-ack;2.4.53;10;cpe:/a:apache:http_server:2.4.53
```

```
$ python pynmap.py -hosts 127.0.0.1 -o json

{"nmap": {"command_line": "nmap -oX - -p 1-1024 -v -sV -Pn 127.0.0.1", "scaninfo": {"error": ["Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.\n"], "tcp": {"method": "connect", "services": "1-1024"}}, "scanstats": {"timestr": "Sat Apr  2 20:54:52 2022", "elapsed": "6.93", "uphosts": "1", "downhosts": "0", "totalhosts": "1"}}, "scan": {"127.0.0.1": {"hostnames": [{"name": "localhost", "type": "PTR"}], "addresses": {"ipv4": "127.0.0.1"}, "vendor": {}, "status": {"state": "up", "reason": "user-set"}, "tcp": {"22": {"state": "open", "reason": "syn-ack", "name": "ssh", "product": "OpenSSH", "version": "8.4p1 Debian 5", "extrainfo": "protocol 2.0", "conf": "10", "cpe": "cpe:/o:linux:linux_kernel"}, "80": {"state": "open", "reason": "syn-ack", "name": "http", "product": "Apache httpd", "version": "2.4.53", "extrainfo": "(Debian)", "conf": "10", "cpe": "cpe:/a:apache:http_server:2.4.53"}}}}}
```


> Exemplo para busca automática de CVE

```
$ python pynmap.py -hosts localhost --cve

================================================================================
Host: 127.0.0.1 (localhost)	Status: up 
Porta: 22	Status: open	Nome: ssh	Produto: OpenSSH
	> CVE-2021-41617    	7.0	privilege escalation when AuthorizedKeys or AuthorizedPrinc are configured
Porta: 80	Status: open	Nome: http	Produto: Apache httpd
	> CVE-2022-24921    	7.5	regexp: stack exhaustion via a deeply nested expression
	> CVE-2021-44521    	9.1	RCE for scripted UDFs
	> CVE-2021-25939    	2.7	Blind SSRF via Foxx service download
```


## Ajuda:

```
$ python pynmap.py -h

usage: pynmap.py [-h] -hosts hosts [hosts ...] [-ports ports] [-arguments arguments] [-arguments_conf arguments_conf] [-t timeout]
                 [-v]

Script em python que recebe um (ou uma lista) de hosts por parâmetro, e realiza um port scan através de integração do python e nmap.
O código é resiliente a travamentos do nmap, pois caso ele não retorne a resposta em até 1 minuto (ou tempo parametrizado), a ação é
interrompida retornando o status de erro. O script está preparado para diferentes outputs.

optional arguments:
  -h, --help            show this help message and exit
  -hosts hosts [hosts ...]
                        Envie um ou mais destinos
  -ports ports          Defina as portas alvo (em sintaxe nmap)
  -arguments arguments  Envie para o nmap expressamente os argumentos
  -arguments_conf arguments_conf
                        Envie para o nmap a configuração do argumento (verifique o file virtual enviroment)
  -t timeout, -timeout timeout, --timeout timeout
                        Timeout em segundos. (Padrao: 60 segundos)
  -v, -version, --version, -V
                        Versão do pynmap.py
```                        

## Disclaimer:

> O desenvolvedor se isenta de qualquer responsabilidade legal referente a má utilização do script (ou parte dele), significando assim que, a execução é de total resposnsabilidade de seu utilizador.
