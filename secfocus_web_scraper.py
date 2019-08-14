#!/usr/bin/env python3

import logging
import csv

import requests_html
import json

base_url = 'https://www.securityfocus.com/bid/'

logging.basicConfig(format='[%(asctime)s %(levelname)s]: %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p',
                    level='INFO')

KEYS = ['Title', 'Bugtraq ID', 'Class', 'CVE', 'Remote', 'Local', 'Published', 'Updated', 'Credit', 'Vulnerable', 'Not Vulnerable']

def start_parser(save_path, start_from_id=1, max_faulty_seqence=10):
    url_prefix = "https://www.securityfocus.com/bid"
    vuln_id = start_from_id
    faulty_sequence = 0
    saved_vulnerabilities = 0

    logging.info(f"Collecting vulnerabilities starting from #{start_from_id}")
    with open(save_path, mode='w') as json_file:
        pass

    with requests_html.HTMLSession() as session:
        while True:
            r = session.get(f"{url_prefix}/{vuln_id}")
            try:
                v = r.html.find("#vulnerability", first=True)
                title = v.find(".title", first=True).text
                logging.info(f"Found \"{title}\"")
                faulty_sequence = 0
                vulnerability = {'title': title}
            except AttributeError:
                faulty_sequence += 1
                if faulty_sequence > max_faulty_seqence:
                    logging.info(f"Done parsing. Phew! Found {saved_vulnerabilities} vulnerabilities")
                    break
                else:
                    logging.info(f"Vulnerability #{vuln_id} not found, skipping. Will drop after {max_faulty_seqence-faulty_sequence} more faulty request(s)")
                    vuln_id += 1
            else:
                for el in v.find("tr"):
                    try:
                        descr_tags = el.find("td")
                        assert len(descr_tags) == 2
                        key, value = [t.text for t in descr_tags]
                        key = key.strip(':').lower().replace(' ', '_')
                        vulnerability[key] = value
                    except AssertionError:
                        pass
                vulnerability['url'] = base_url + str(vulnerability['bugtraq_id'])
                with open(save_path, mode='a') as json_file:
                    # json.dump(vulnerability, json_file)
                    json_file.write(json.dumps(vulnerability))
                    json_file.write('\n')
                    saved_vulnerabilities += 1
                vuln_id += 1


if __name__ == '__main__':
    import pandas as pd
    pd.set_option('display.max_rows', 500)
    pd.set_option('display.max_columns', 500)
    pd.set_option('display.width', 1000)
    start_parser(save_path="vulnerabilities.json",
                 start_from_id=1,
                 max_faulty_seqence=100)
