#!/usr/bin/env python3
import os
import re
import ipaddress
import ruamel.yaml
yaml = ruamel.yaml.YAML()
yaml.indent(sequence=4, offset=2)

os.system('clear')

RULES_DIR = os.path.expanduser('~/Developer/Clash/Rules/rules/provider/')
files_ip = [
    "localIP.yaml",
    "usIP.yaml",
    "netflixIP.yaml",
    "neteaseMusicIP.yaml",
    "googleFCMIP.yaml",
    "bilibiliIP.yaml",
    "appleDirectIP.yaml",
    "youtubeIP.yaml",
    "mainlandIP.yaml",
    "mediaIP.yaml",
    "mediaBlockedIP.yaml",
    "socialMediaIP.yaml",
    "gameIP.yaml",
    "blockedIP.yaml"
]
files = [
    "localDomain.yaml",
    "hkDomain.yaml",
    "gptClassical.yaml",
    "gptDomain.yaml",
    "intranetPenetrationClassical.yaml",
    "financeClassical.yaml",
    "financeDomain.yaml",
    "netflixClassical.yaml",
    "netflixDomain.yaml",
    "neteaseMusicDomain.yaml",
    "googleFCMDomain.yaml",
    "bilibiliClassical.yaml",
    "bilibiliDomain.yaml",
    "appleDirectClassical.yaml",
    "appleDirectDomain.yaml",
    "appleBlockedClassical.yaml",
    "appleBlockedDomain.yaml",
    "youtubeClassical.yaml",
    "youtubeDomain.yaml",
    "mainlandClassical.yaml",
    "mainlandDomain.yaml",
    "mediaClassical.yaml",
    "mediaDomain.yaml",
    "mediaBlockedClassical.yaml",
    "mediaBlockedDomain.yaml",
    "socialMediaClassical.yaml",
    "socialMediaDomain.yaml",
    "gameClassical.yaml",
    "gameDomain.yaml",
    "usClassical.yaml",
    "usDomain.yaml",
    "speedtestClassical.yaml",
    "speedtestDomain.yaml",
    "scholarClassical.yaml",
    "scholarDomain.yaml",
    "blockedClassical.yaml",
    "blockedDomain.yaml"
]

files_domain = [f for f in files if f.endswith("Domain.yaml")]
files_classical = [f for f in files if f.endswith("Classical.yaml")]

def load_rules(file_list):
    rules = []
    for f in file_list:
        path = RULES_DIR + f
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.load(f)
            if 'payload' in data:
                payload_list = data['payload']
                payload_list.sort()
                rules.append(payload_list)

    return rules

def deduper(file_list):

    rules = [list(dict.fromkeys(sublist)) for sublist in file_list]

    return rules

def dedup_inter_classical(rules):
    i = 0
    while i < len(rules):
        j = i + 1
        while j < len(rules):
            k = 0
            flag = 0
            while k < len(rules[i]):
                l = flag
                while l < len(rules[j]):
                    if re.match(rules[i][k], rules[j][l]):
                        del rules[j][l]
                        flag = l
                    else:
                        l += 1
                k += 1
            j += 1
        i += 1
    return rules

def remove_keyword(rules):

    flagged_keywords = set()
    updated_rules = []

    for sublist in rules:

        new_keywords = [item.split('DOMAIN-KEYWORD,')[1] for item in sublist if 'DOMAIN-KEYWORD,' in item]
        flagged_keywords.update(new_keywords)

        updated_rules.append(sublist[:])
        

        for other_sublist in rules[rules.index(sublist)+1:]:
            other_sublist[:] = [item for item in other_sublist if not any(keyword in item for keyword in flagged_keywords)]

def domain_deduper(rules):

    rules = [x[:] for x in rules]

    def sort1(rules):
        rules = []
        for sublist in rules:
            sublist = [element.replace("+", "") for element in sublist]
            sublist = [element[::-1] for element in sublist]
            sublist.sort()
            rules.append(sublist)
        return rules

    def dedup_inter_domain(rules):
        i = 0
        while i < len(rules):
            j = i + 1
            while j < len(rules):
                k = 0
                flag = 0
                while k < len(rules[i]):
                    l = flag
                    while l < len(rules[j]):
                        if re.match(rules[i][k], rules[j][l]):
                            del rules[j][l]
                            flag = l
                        else:
                            l += 1
                    k += 1
                j += 1
            i += 1
        return rules

    def sort2(rules):
        rules = []
        for sublist in rules:
            sublist = [element[::-1] for element in sublist] 
            sublist = ['+' + element for element in sublist]
            sublist.sort()
            rules.append(sublist)
        return rules

    rules = sort1(rules)
    rules = dedup_inter_domain(rules)
    rules = sort2(rules)

    return rules

def ip_deduper(rules):

    def sort_cidrs(cidrs):
        return sorted(cidrs, key=lambda x: x[1].network_address)

    def dedup_cidrs(cidrs):

        i = 0
        while i < len(cidrs) - 1:
            if cidrs[i][1] == cidrs[i+1][1]: 

                del cidrs[i+1]
            elif cidrs[i][1].network_address <= cidrs[i+1][1].network_address and \
                cidrs[i][1].broadcast_address >= cidrs[i+1][1].broadcast_address:

                del cidrs[i+1]
            else:
                i += 1

        return cidrs

    for file_rules in rules:

        ipv4_cidrs = []
        ipv6_cidrs = []

        for rule in file_rules:
            cidr = ipaddress.ip_network(rule, strict=False)
            if cidr.version == 4:
                ipv4_cidrs.append((rule, cidr))
            else:
                ipv6_cidrs.append((rule, cidr))
        ipv4_cidrs = sort_cidrs(ipv4_cidrs)
        ipv6_cidrs = sort_cidrs(ipv6_cidrs)   
        ipv4_cidrs = dedup_cidrs(ipv4_cidrs)
        ipv6_cidrs = dedup_cidrs(ipv6_cidrs)
        file_rules[:] = [cidr[0] for cidr in ipv4_cidrs + ipv6_cidrs]
    return rules

def dedup_inter_ip(rules):

    cidr_lists_v4 = [[] for _ in rules]
    cidr_lists_v6 = [[] for _ in rules]

    i = 0
    while i < len(rules):
        for rule in rules[i]:
            cidr = ipaddress.ip_network(rule, strict=False)
            if cidr.version == 4:
                cidr_lists_v4[i].append(cidr) 
            else:
                cidr_lists_v6[i].append(cidr)
        i += 1

    def dedup_cidrs(cidrs):
        i = 0
        while i < len(cidrs):
            j = i + 1
            while j < len(cidrs):
                k = 0
                flag = 0
                while k < len(cidrs[i]):
                    l = flag
                    while l < len(cidrs[j]):
                        if cidrs[i][k].network_address <= cidrs[j][l].network_address and \
                            cidrs[i][k].broadcast_address >= cidrs[j][l].broadcast_address:

                            del cidrs[j][l]
                            flag = l
                        else:
                            l += 1
                    k += 1
                j += 1
            i += 1
        return cidrs

    cidr_lists_v4 = dedup_cidrs(cidr_lists_v4)
    cidr_lists_v6 = dedup_cidrs(cidr_lists_v6)
    result = []

    for i in range(len(cidr_lists_v4)):
        tmp = []
        for cidr in cidr_lists_v4[i]:
            tmp.append(str(cidr))
        for cidr in cidr_lists_v6[i]:
            tmp.append(str(cidr))
        result.append(tmp)

    return result

def save_rules(file_list, data):
    for f, payload_list in zip(file_list, data):
        path = RULES_DIR + f

        data_to_save = {'payload': payload_list}

        with open(path, 'w', encoding='utf-8') as f:
            yaml.dump(data_to_save, f)

def main():

    other_rules = load_rules(files)
    other_rules = deduper(other_rules)
    remove_keyword(other_rules)
    save_rules(files, other_rules)
    classical_rules = load_rules(files_classical)
    classical_rules = dedup_inter_classical(classical_rules)
    save_rules(files_classical, classical_rules)

    domain_rules = load_rules(files_domain)
    domain_rules = domain_deduper(domain_rules)
    save_rules(files_domain, domain_rules)

    ip_rules = load_rules(files_ip)
    ip_rules = ip_deduper(ip_rules)
    ip_rules = dedup_inter_ip(ip_rules)
    save_rules(files_ip, ip_rules)

if __name__ == '__main__':
    main()
