#!/usr/bin/env python3

def get_arguments():
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-s', '--search',
                        dest='search',
                        required=True,
                        help='Search query')
    parser.add_argument('-f', '--file',
                        default='/usr/share/exploitdb/vulnerabilities.json',
                        help='A CSV file with scraped vulnerabilities',
                        dest='file')
    options = parser.parse_args()

    return options

import json

def search(search_query, file_name):

    vulns = [json.loads(vuln.replace('\n', '')) for vuln in open(file_name, 'r').readlines()]

    matched_vulns = 0
    for v in vulns:
        if search_query.lower() in v['title'].lower():
            matched_vulns += 1
            print(f"{matched_vulns}. {v['title']}")
            print(v['url'])
            print('')



options = get_arguments()

search(options.search, options.file)
