#!/usr/bin/env python3
import json

VULNERABILITIES_JSON_FILE = "/usr/share/exploitdb/vulnerabilities.json"


def get_arguments():
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-s', '--search',
                        dest='search',
                        required=True,
                        help='Search for vulnerabilities by it\'s title and software names')
    parser.add_argument('-f', '--file',
                        default=VULNERABILITIES_JSON_FILE,
                        help='A CSV file with scraped vulnerabilities. Default is ' + VULNERABILITIES_JSON_FILE,
                        dest='file')
    parser.add_argument('-v', '--verbose',
                        action='store_true',
                        required=False,
                        help='Be verbose, print additional information')
    options = parser.parse_args()

    return options


class Vuln:
    def __init__(self, id, vuln_json):
        def fieldOrNone(field):
            if vuln_json[field] and vuln_json[field].strip() != '':
                return vuln_json[field]

        self.id = id
        self.title = fieldOrNone('title')
        self.url = fieldOrNone('url')
        # additional information
        self.cve = fieldOrNone('cve')
        self.vulnerable_software = fieldOrNone('vulnerable')

    def printout(self, verbose):
        print(f"{self.id}. {self.title}")
        if self.url:
            print(self.url)
        if verbose:
            if self.cve:
                print(self.cve)
            if self.vulnerable_software:
                print(self.vulnerable_software)

        print('*' * 50)


def search(search_query, file_name):
    vulns = [json.loads(vuln.replace('\n', '')) for vuln in open(file_name, 'r').readlines()]

    matched_count = 0
    results = []
    for v in vulns:
        if search_query.lower() in v['title'].lower() or search_query.lower() in str(v['vulnerable']).lower():
            matched_count += 1
            results.append(Vuln(matched_count, v))
    return results


options = get_arguments()

vulns = search(options.search, options.file)
for v in vulns:
    v.printout(options.verbose)
