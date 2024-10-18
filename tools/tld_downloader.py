#!/usr/bin/python3

# Read the TLD data from https://tld-list.com/df/tld-list-details.json

import argparse
import json


def read_tld_data(file_path):
    with open(file_path) as f:
        return json.load(f)


def filter_and_split_tlds(tld_data, tld_type):
    sponsored = []
    unsponsored = []
    for k, v in tld_data.items():
        if v['type'] == tld_type:
            if v.get('sponsor'):
                sponsored.append(k)
            else:
                unsponsored.append(k)
    return sponsored, unsponsored


def main():
    parser = argparse.ArgumentParser(description='Filter TLD data from a local file')
    parser.add_argument('--file', default='tld-list-details.json', help='Input file containing TLD data')
    parser.add_argument('--type', choices=['gTLD', 'ccTLD'], help='Filter TLDs by type')
    parser.add_argument('--output', default='filtered_tld_list', help='Base name for output files')

    args = parser.parse_args()

    tld_data = read_tld_data(args.file)

    if args.type:
        sponsored, unsponsored = filter_and_split_tlds(tld_data, args.type)
    else:
        sponsored, unsponsored = filter_and_split_tlds(tld_data, None)

    with open(f'{args.output}_sponsored.json', 'w') as f:
        json.dump(sponsored, f, indent=4)

    with open(f'{args.output}_unsponsored.json', 'w') as f:
        json.dump(unsponsored, f, indent=4)

    print(f'Sponsored TLDs have been saved to {args.output}_sponsored.json')
    print(f'Unsponsored TLDs have been saved to {args.output}_unsponsored.json')


if __name__ == '__main__':
    main()
