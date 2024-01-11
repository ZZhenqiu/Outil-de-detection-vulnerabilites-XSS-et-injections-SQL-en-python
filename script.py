import sys
import requests
from termcolor import colored

def detect_xss_vulnerability(url):
    try:
        response = requests.get(url)
        response.raise_for_status()

        html_content = response.text

        # Liste de chaînes communes potentiellement dangereuses (à adapter si besoin)
        dangerous_strings = ['<script', 'javascript:', 'onerror', 'alert(']

        vulnerability_found = any(dangerous_string in html_content for dangerous_string in dangerous_strings)

        if vulnerability_found:
            print("\n" + colored(f"Potentielle vulnérabilité XSS : {url}", 'red') + "\n")
        else:
            print("\n" + colored(f"Aucune vulnérabilité XSS : {url}", 'yellow') + "\n")

    except requests.exceptions.RequestException as e:
        print("\n" + colored(f"Erreur: {e}", 'yellow'))

def check_sql_injection(url):
    try:
        response = requests.get(url, timeout=5)
        
        if "error" in response.text.lower():
            print(colored(f"Potentielle vulnérabilité d'injection SQL : {url}", 'red') + "\n")
        else:
            print(colored(f"Aucune vulnérabilité d'injection SQL: {url}", 'yellow') + "\n")

    except Exception as e:
        print()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("\n" + colored("Bonjour, pour pouvoir utiliser ce programme : python script.py <url>", 'yellow') + "\n")
        sys.exit(1)

    url_to_check = sys.argv[1]

    # Check for XSS vulnerability
    detect_xss_vulnerability(url_to_check)

    # Check for SQL injection vulnerability
    check_sql_injection(url_to_check)
