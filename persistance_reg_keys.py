#!/usr/bin/env python3

import argparse
import requests
import re
import sys

base_url = "https://attack.mitre.org"
persistance_path = "/tactics/TA0003/"

key_search_terms = ["HKEY", "HKCR", "HKCU", "HKLM", "HKU"]

target_links = []
register_keys = []


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--outfile", dest="outfile", nargs='?', default="persistance_keys.txt",
                        help="Outfile storing register keys")

    opts = parser.parse_args()
    return opts


def extract_technique_links(url):
    try:
        response = requests.get(url)

        href_links = re.findall('(?:href=")(/techniques/T.*?)"', response.content.decode('UTF-8'))
        href_links_no_duplicates = list(set(href_links))

        return href_links_no_duplicates

    except requests.exceptions.ConnectionError:
        print("[-] Could not get response from MITRE server.")
        exit(1)


def extract_register_keys(url):
    response = requests.get(url)

    keys = []

    # Find all uses of HKEY and other variations
    for word in key_search_terms:
        search_results = re.findall('<code>(' + word + '.+?)</code>', response.content.decode('UTF-8'))

        # If unique, add to register keys list
        if search_results:
            for result in search_results:
                if result not in register_keys:
                    register_keys.append(result)


def search_paths_for_register_keys(paths):
    count = 1
    number_of_paths = len(paths)

    for path in paths:
        print("\r[+] Scanning MITRE ATT&CK web site " + str(count) + "/" + str(
            number_of_paths) + " for persistance register keys...", end="")
        sys.stdout.flush()
        count += 1
        extract_register_keys(base_url + path)


def write_keys_to_file(register_keys, outfile):
    if register_keys:
        number_of_keys_found = len(register_keys)

        try:
            with open(outfile, "w") as file:
                for line in register_keys:
                    file.write(str(line) + "\n")
                print("\n[+] Found " + str(number_of_keys_found) + " keys. Wrote register key output to: " + str(
                    outfile) + ".")
        except:
            print("[-] Could not open file " + str(outfile) + " for writing.")


if __name__ == "__main__":
    opt = get_arguments()

    technique_paths = extract_technique_links(base_url + persistance_path)

    search_paths_for_register_keys(technique_paths)

    write_keys_to_file(register_keys, opt.outfile)
