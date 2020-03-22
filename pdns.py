#!/usr/bin/python
# Name: pdns.py - a trimmed class of Maltelligence Tool
# By:   Frankie Li
# Created:  Dec 25, 2014
# Modified: Mar 26, 2015
# Function: Class of query passive dns sources (VirusTotal and mnemonic Pdns)
# See the file 'LICENSE' for copying permission.
#
#   Usage, can called by Passive.py or used inside a python prompt
#   1.  from pdns import pdns       // import the class
#   2.  p = pdns()                  // create an instance
#   3.  p.get_Pip(domain)           // query virusTotal passive dns by a domain
#   4.  p.get_Pdns(ip)              // query virusTotal passive dns by an ip address
#   5.  p.get_mnPdns(domain|ip)     // query mnemonic Passive dns by domain or ip address
#   6.  p.get_download(hash, tag)   // download sample from virusTotal to file system of a folder named with the tag
#   7.  p.findPassive(domain)       // query virusTotal recurrsively according to VTDEPTH level
#
#   [-] Please make provide VirusTotal Keys ... !   // you need to provide valid keys in MalProfile.ini
#                                                   // without double-quotes or single-quotes
#
#   To keep queries instead of reading messy data from stdout:
#
#   as_owner, asn, country, urls, downloaded, communicating, resolutions = get_Pdns(ip)
#   urls, downloaded, communicating, resolutions = get_Pip(domain)
#


import sys
import json
import urllib
import urllib2
import re
import ConfigParser
import requests
import time
import os
import hashlib
from prettytable import PrettyTable

try:
    config_ini = "/opt/remnux-pdns/MalProfile.ini"
    config = ConfigParser.ConfigParser()
    config.read(config_ini)
    VT_APIKEY = config.get("API_KEYS", "VT_APIKEY")
    VTLIMIT = config.get("VT_4", "VTLIMIT")
    VTDEPTH = int(config.get("VT_4", "VTDEPTH"))
    MN_APITKEY = config.get("mnemonic", "KEY")
except:
    print("[-] Error reading config file: " + config_ini + " ... !")
    sys.exit()

if VT_APIKEY == '' or VTLIMIT == 0 or VTDEPTH == 0:
    print "\n[-] Please provide Keys at MalProfile.ini... !\n"
    sys.exit()
#else:
    #   add '#' at beginning of the print statement to hide this message, if you don't like it ;)
    #print "\n\n[+] Making queries to VirusTotal with depth level of %s, \nand Key=%s\n" % (VTDEPTH, VT_APIKEY)


class pdns(object):
    
    #   VT_LIMIT = 4, can be removed if user obtained commerical license from VirusTotal
    #   https://www.virustotal.com/en/faq/ (The 4 requests/minute limitation)
    
    def __init__(self):
        pass

    def chk_ip(self, data):
        """ check if it is an IP address. True or False
            """
        parts = data.split('.')
        return (
                len(parts) == 4
                and all(part.isdigit() for part in parts)
                and all(0 <= int(part) <= 255 for part in parts)
                )

    def chk_domain(self, data):
        """ check if it is an Domain. True or False
            """
        if self.chk_ip(data):
            return False
        else:
            regex = '[a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63})*'
            p = re.compile(regex)
            matched = p.search(data)
            if matched.lastindex == 1:
                return True
            else:
                return False

    def md5sum(self, data):
        """ return md5 hash from data provided
            """
        md5 = hashlib.md5()
        md5.update(data)
        return md5.hexdigest()



    def get_Pdns(self, data):
        """ assume ip address is supplied """

        try:
            as_owner = []
            asn = []
            country = []
            urls = []               ##  dictionary list
            downloaded = []         ##  dictionary list
            communicating = []      ##  dictionary list
            resolutions = []        ##  dictionary list

            if self.chk_ip(data):
                ip = data
                url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
                parameters = {'ip': ip, 'apikey': VT_APIKEY}
                response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
                res = json.loads(response)
                print "[+] Checking ip address = %s ..." % (ip)
                
                if res.get('response_code') == 1:
                    
                    if res.get('as_owner'):
                        as_owner = res.get('as_owner')

                    if res.get('asn'):
                        asn = res.get('asn')

                    if res.get('country'):
                        country = res.get('country')
                    
                    #   keys: 'url', 'positives', 'scan_date'
                    if res.get('detected_urls'):
                        urls = res.get('detected_urls')
                    
                    #   keys: 'date', 'positives', 'sha256'
                    if res.get('detected_downloaded_samples'):
                        downloaded = res.get('detected_downloaded_samples')
                    
                    #   keys: 'date', 'positives', 'sha256'
                    if res.get('detected_communicating_samples'):
                        communicating = res.get('detected_communicating_samples')
                    
                    #   keys: 'last_resolved', 'hostname'
                    if res.get('resolutions'):
                        resolutions = res.get('resolutions')
        
            return as_owner, asn, country, urls, downloaded, communicating, resolutions
    
        except:
            return ''


    def get_Pip(self, data):
        """ assume domain is supplied """

        try:
            urls = []               ##  dictionary list
            downloaded = []         ##  dictionary list
            communicating = []      ##  dictionary list
            resolutions = []        ##  dictionary list

            if self.chk_domain(data):
                domain = data
                url = 'https://www.virustotal.com/vtapi/v2/domain/report'
                parameters = {'domain': domain, 'apikey': VT_APIKEY}
                response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
                res = json.loads(response)
                print "[+] Checking domain = %s ..." % (domain)
            
                if res.get('response_code') == 1:
                    
                    #   keys: 'url', 'positives', 'scan_date'
                    if res.get('detected_urls'):
                        urls = res.get('detected_urls')
                    
                    #   keys: 'date', 'positives', 'sha256'
                    if res.get('detected_downloaded_samples'):
                        downloaded = res.get('detected_downloaded_samples')
                    
                    #   keys: 'date', 'positives', 'sha256'
                    if res.get('detected_communicating_samples'):
                        communicating = res.get('detected_communicating_samples')
                    
                    #   keys: 'last_resolved', 'ip_address'
                    if res.get('resolutions'):
                        resolutions = res.get('resolutions')
                            
            return urls, downloaded, communicating, resolutions
        except:
            return ''


    def get_download(self, hash, tag):
        """ assume hash supplied """
        #search_url = ('https://www.virustotal.com/intelligence/search/programmatic/')
        download_url = ('https://www.virustotal.com/intelligence/download/?hash=%s&apikey=%s')
        folder = './'
        response = None
        page = None
        folder_name = time.strftime('%Y%m%d_'+tag)
        if not os.path.exists(folder):
            os.mkdir(folder)
        folder_path = os.path.join(folder, folder_name)
        if not os.path.exists(folder_path):
            os.mkdir(folder_path)
        destination_file = os.path.join(folder_path, hash)
        #destination_file = folder_path
        parameters = {'query': hash, 'apikey': VT_APIKEY, 'page': page}
        data = urllib.urlencode(parameters)
        url = download_url % (hash, VT_APIKEY)
        success =  urllib.urlretrieve(url, destination_file)
        if success:
            print "[+] " + folder_name + " download was successful"
        else:
            print "[+] " + folder_name + " download was failed"


    def get_mnPdns(self, data):
        """ get mnemonic Pdns from ip or dns """

        #   init varaibles
        c2 = []
        #   Check MN_APITKEY
        if MN_APITKEY == '':
            print "\n[-] Please provide mnemonic Pdns Key at MalProfile.ini... !"
        else:
            print "\n[+] Using mnemonic Pdns key: %s" % (MN_APITKEY)
        
        base_url = "http://passivedns.mnemonic.no/api1/?"
        url = base_url + "apikey=" + MN_APITKEY + "&query=" + data + "&method=" + "exact"
        response = requests.get(url)
        res = json.loads(response.text)

        #   keys: 'query', 'first'
        if res.get('message') == 'ok':
            found = res.get('result')
            for i in range(0, len(found)):
                entry = (dict(query=data, answer=found[i]['answer']))
                c2.append(entry)
                
            #   print c2 table
            print "[+] mnemonic pdns results ..."
            table = PrettyTable(['query','answer'])
            table.align = 'l'
            for i in range(0, len(c2)):
                #   ordering the data
                query = c2[i].get('query')
                answer = c2[i].get('answer')
                #   adding to table for showing to console
                line = (query, answer)
                table.add_row(line)
                    
            print table

            #return found
        #else:
            #return {}


    def findPassive(self, data):
        """ return recurrsive passive DNS info from VirusTotal
            """
        c2 = []
        as_owners = []
        uri = []
        downloads = []
        comms = []
        
        entry = {}
        row = 0
        processed = 0
        localhost = "127.0.0.1"
        
        #   query virusTotal
        while (processed <= int(VTDEPTH) and processed <= len(c2)):
            
            # control VT_LIMIT = 4
            if (processed)%4 == 0 and VTLIMIT == "True" and processed != 0:
                print "[+] Pausing 1 min ..... = " + str(processed) +'/' + str(VTDEPTH)
                time.sleep(60)
            
            #   query virusTotal
            if processed != 0:
                data = c2[processed-1].get('_to')
            
            processed = processed + 1
            
            if (self.chk_ip(data) and data != localhost):
                as_owner, asn, country, urls, downloaded, communicating, resolutions = self.get_Pdns(data)
                
                #   add 1st 10 resolutions
                if len(resolutions) > 10:
                    records = 10
                else:
                    records = len(resolutions)
                for i in range(0, records):
                    ip = data
                    dns = resolutions[i].get('hostname')
                    hash = self.md5sum(dns+'-'+ip)
                    date = resolutions[i].get('last_resolved').split(" ")[0]
                    entry = (dict(id=row+1, from_=ip, dns_ip=hash , _to=dns, date=date,c2_id=processed-1))
                    #   is_duplicated is False, add entry to c2 list
                    is_duplicated = False
                    for j in range(0, len(c2)):
                        if c2[j].get('dns_ip') == hash:
                            is_duplicated = True
                    if is_duplicated is False:
                        row = row + 1
                        c2.append(entry)
            
                #   add as_owner
                if as_owner and asn:
                    entry = (dict(source=data, owner=as_owner, num=asn, cn=country))
                    as_owners.append(entry)
        
                #   add urls
                for i in range(0, len(urls)):
                    entry = (dict(source=data, url=urls[i].get('url'), date=urls[i].get('scan_date').split(" ")[0]))
                    uri.append(entry)
                
                #   add downloaded
                for i in range(0, len(downloaded)):
                    entry = (dict(id=i, source=data, date=downloaded[i].get('date').split(" ")[0], hash=downloaded[i].get('sha256')))
                    is_duplicated = False
                    for j in range(0, len(downloads)):
                        if downloads[j].get('sha256') == hash:
                            is_duplicated = True
                    if is_duplicated is False:
                        downloads.append(entry)
        
                #   add communicating
                for i in range(0, len(communicating)):
                    entry = (dict(id=i, source=data, date=communicating[i].get('date').split(" ")[0], hash=communicating[i].get('sha256')))
                    is_duplicated = False
                    for j in range(0, len(communicating)):
                        if communicating[j].get('sha256') == communicating[i].get('sha256'):
                            is_duplicated = True
                    if is_duplicated is False:
                        comms.append(entry)
                        
            else:
                urls, downloaded, communicating, resolutions = self.get_Pip(data)

                #   add 1st 10 resolutions
                if len(resolutions) > 10:
                    records = 10
                else:
                    records = len(resolutions)
                for i in range(0, records):
                    dns = data
                    ip = resolutions[i].get('ip_address')
                    hash = self.md5sum(dns+'-'+ip)
                    date = resolutions[i].get('last_resolved').split(" ")[0]
                    entry = (dict(id=row+1, from_=dns, _to=ip, dns_ip=hash , date=date,c2_id=processed-1))
                    #   is_duplicated is False, add entry to c2 list
                    is_duplicated = False
                    dns_id = 0
                    ip_id = 0
                    for j in range(0, len(c2)):
                        if c2[j].get('dns_ip') == hash:
                            is_duplicated = True
                    if is_duplicated is False:
                        row = row + 1
                        c2.append(entry)

                #   add urls
                for i in range(0, len(urls)):
                    entry = (dict(source=data, url=urls[i].get('url'), date=urls[i].get('scan_date').split(" ")[0]))
                    uri.append(entry)
                
                #   add downloaded
                for i in range(0, len(downloaded)):
                    entry = (dict(id=i, source=data, date=downloaded[i].get('date').split(" ")[0], hash=downloaded[i].get('sha256')))
                    is_duplicated = False
                    for j in range(0, len(downloads)):
                        if downloads[j].get('sha256') == hash:
                            is_duplicated = True
                    if is_duplicated is False:
                        downloads.append(entry)
            
                #   add communicating
                for i in range(0, len(communicating)):
                    entry = (dict(id=i, source=data, date=communicating[i].get('date').split(" ")[0], hash=communicating[i].get('sha256')))
                    is_duplicated = False
                    for j in range(0, len(communicating)):
                        if communicating[j].get('sha256') == hash:
                            is_duplicated = True
                    if is_duplicated is False:
                        comms.append(entry)

        #   print c2 table
        print "[+] recursive pdns results ..."
        table = PrettyTable(['id','from','to','date','c2_id'])
        table.align = 'l'
        for i in range(0, len(c2)):
            #   ordering the data
            table_id = c2[i].get('id')
            scan_date = c2[i].get('date')
            from_ = c2[i].get('from_')
            _to = c2[i].get('_to')
            c2_id = c2[i].get('c2_id')
            #   adding to table for showing to console
            line = (table_id, from_, _to, scan_date, c2_id)
            table.add_row(line)
        print table
            
        #   print as_owners table
        print "[+] IP addresses and their owner & AS numbers ..."
        table = PrettyTable(['source','owner','AS','country'])
        table.align = 'l'
        for i in range(0, len(as_owners)):
            line = (as_owners[i].get('source'), as_owners[i].get('owner'), as_owners[i].get('num'), as_owners[i].get('cn'))
            table.add_row(line)
        print table

        #   print uri table
        table = PrettyTable(['source','url','scan_date'])
        table.align = 'l'
        for i in range(0, len(uri)):
            line = (uri[i].get('source'), uri[i].get('url'), uri[i].get('date'))
            table.add_row(line)
        #print table
    
        #   print downloads table
        print "[+] All matched downloads ..."
        table = PrettyTable(['id', 'source','date','hash'])
        table.align = 'l'
        for i in range(0, len(downloads)):
            line = (downloads[i].get('id'), downloads[i].get('source'), downloads[i].get('date'), downloads[i].get('hash'))
            table.add_row(line)
        print table

        #   print comms table
        table = PrettyTable(['id', 'source','date','hash'])
        table.align = 'l'
        for i in range(0, len(comms)):
            line = (comms[i].get('id'), comms[i].get('source'), comms[i].get('date'), comms[i].get('hash'))
            table.add_row(line)
        #print table

        #   In case using in Python shell, remove the '#' can keep the return values 
        #return as_owners, uri, downloads, comms, c2


