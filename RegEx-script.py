"""
Sript that will analyze and extract info from access log file
"""


# Importing modules required to run
import os
import re

# Prompts user for file name and find path provided by lecture
log_file = input("What file do you want to scan? ")
dir_path = os.path.dirname(os.path.realpath(__file__))

# Only change is using "with open" as it's concidered best practice
with open(dir_path + "/" + log_file, "r") as f:
    log_lines = f.readlines()

# Search patterns and results dictionary
re_code_pattern = r"\s\d{3}\s"
re_ipaddress_pattern = r"^((\d{1,3}\.){3})\d{1,3}"

# Function for finding Status codes
def analyze_status_codes():
    code_flag_dict ={}
    # looks through file using RegEx pattern
    for line in log_lines:
        m = re.search(re_code_pattern, line)
        if m:
            status_code = m.group()
        # Saves matched codes to dictionary
            if status_code in code_flag_dict.keys():
                code_flag_dict[status_code] += 1
            else:
                code_flag_dict[status_code] = 1
    # Sort results for readibility
    for k, v in code_flag_dict.items():
        print(f" Codes:{k} Flags: {v}")


# Function for finding IP Addresses
def identify_highest_traffic():
    ip_flag_dict ={}
    for line in log_lines:
        m = re.search(re_ipaddress_pattern, line)
        if m:
            ip = m.group()
            if ip in ip_flag_dict.keys():
                ip_flag_dict[ip] += 1
            else:
                ip_flag_dict[ip] = 1

    # Finds IP with most traffic and value
    ipm = max(ip_flag_dict, key=ip_flag_dict.get)
    ipv = ip_flag_dict[ipm]
    # Sum of values in dict
    s = sum(ip_flag_dict.values())
    # Gets % on highest value
    pct = ip_flag_dict[ipm] * 100.0 / s
    return ipm, ipv, pct

def main():
    analyze_status_codes()
    ipm, ipv, pct =identify_highest_traffic()
    print(f" Most frequent IP: {ipm}\n Flags: {ipv}\n Percentage of Log: {pct}")
    
main()


"""
from urllib.parse import urlparse

urlparse("scheme://netloc/path;parameters?query#fragment")

re_url_pattern = r"https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)"
url_dict = {}

for line in log_lines:
    m = re.search(re_url_pattern, line)
    u = urlparse(m)
    print(u)
    
        if m:
        url_links = m.group()
        if url_links in url_dict.keys():
            url_dict[url_links] += 1
        else:
            url_dict[url_links] = 1
    
print(url_dict)
"""


