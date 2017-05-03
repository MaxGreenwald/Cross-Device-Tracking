
# coding: utf-8

# In[1]:

import os
import json
import util
import sqlite3
import pandas as pd
pd.set_option("display.max_colwidth",500)
pd.set_option("display.max_rows",500)

import sys

con = sqlite3.connect('/Users/max1995/Desktop/Thesis/DesktopTraffic/10ksites/10k.sqlite')
cur = con.cursor()


# #This gets and prints all the first party sites visited

# In[12]:

count = 0
for row in cur.execute('SELECT sv.site_url, fb.connect_page_found, fb.connect_successful, fb.fb_api_verified FROM site_visits as sv LEFT JOIN fb_login as fb ON sv.visit_id = fb.visit_id WHERE fb.connect_page_found = 1;'):
    count = count + 1
    print row[0][7:]
print count


# # This searches IDs and their hashes through all first parties and their HTTP requests and exports the PII findings to a CSV

# In[2]:

# Helper functions (TODO let's place this somewhere more central?)
from urlparse import urlparse
import hashlib
import base64
import zlib
import mmh3

def get_requests_with_string(df, string):
    """ Search request url, headers, and post body for string """
    md5_string = hashlib.md5(string).hexdigest()
    sha1_string = hashlib.sha1(string).hexdigest()
    sha256_string = hashlib.sha256(string).hexdigest()
    sha224_string = hashlib.sha224(string).hexdigest()
    sha384_string = hashlib.sha384(string).hexdigest()
    sha512_string = hashlib.sha512(string).hexdigest()
    b64_string = base64.b64encode(string)
    crc32_string = str(zlib.crc32(string))
    adler32_string = str(zlib.adler32(string))
    mmh3_string = str(mmh3.hash(string))
    mmh3_64_string_1 = str(mmh3.hash64(string)[0])
    mmh3_64_string_2 = str(mmh3.hash64(string)[1])
    mmh3_128_string = str(mmh3.hash128(string))
    return df[df.is_tp & (
             df.url.str.contains(string) |
             df.url.str.contains(md5_string) | 
             df.url.str.contains(sha1_string) |
             df.url.str.contains(sha256_string) | 
             df.url.str.contains(sha224_string) | 
             df.url.str.contains(sha384_string) | 
             df.url.str.contains(sha512_string) | 
             df.url.str.contains(b64_string) | 
             df.url.str.contains(crc32_string) | 
             df.url.str.contains(adler32_string) | 
             df.url.str.contains(mmh3_string) | 
             df.url.str.contains(mmh3_64_string_1) |
             df.url.str.contains(mmh3_64_string_2) |
             df.url.str.contains(mmh3_128_string) | 
             df.headers.str.contains(string) |
             df.headers.str.contains(md5_string) | 
             df.headers.str.contains(sha1_string) |
             df.headers.str.contains(sha256_string) | 
             df.headers.str.contains(sha224_string) | 
             df.headers.str.contains(sha384_string) | 
             df.headers.str.contains(sha512_string) | 
             df.headers.str.contains(b64_string) | 
             df.headers.str.contains(crc32_string) | 
             df.headers.str.contains(adler32_string) | 
             df.headers.str.contains(mmh3_string) | 
             df.headers.str.contains(mmh3_64_string_1) |
             df.headers.str.contains(mmh3_64_string_2) |
             df.headers.str.contains(mmh3_128_string) | 
             df.post_body.str.contains(string) |
             df.post_body.str.contains(md5_string) | 
             df.post_body.str.contains(sha1_string) |
             df.post_body.str.contains(sha256_string) | 
             df.post_body.str.contains(sha224_string) | 
             df.post_body.str.contains(sha384_string) | 
             df.post_body.str.contains(sha512_string) | 
             df.post_body.str.contains(b64_string) | 
             df.post_body.str.contains(crc32_string) | 
             df.post_body.str.contains(adler32_string) | 
             df.post_body.str.contains(mmh3_string) | 
             df.post_body.str.contains(mmh3_64_string_1) |
             df.post_body.str.contains(mmh3_64_string_2) |
             df.post_body.str.contains(mmh3_128_string)  
        )]


# In[3]:

# HTTP Requests
import util
requests = pd.read_sql_query("SELECT sv.site_url, r.url, r.headers, r.loading_href, "
                             "r.req_call_stack, r.content_policy_type, r.post_body "
                             "FROM http_requests as r LEFT JOIN site_visits as sv "
                             "ON sv.visit_id = r.visit_id;", con)
util.add_tp_col(requests, 'site_url', 'url')
requests = requests.fillna('')


# In[25]:

import csv
IDs = [
"ids", "more ids"]
count = 1
for pers in IDs:
    norepeats = {}
    reqs = get_requests_with_string(requests,pers)
    #facebook appears on every site all the time! filter it out
    reqs = reqs[~reqs['headers'].str.contains(r'^\[\[\"Host\",\"www.facebook.com')] 
    count = count+1
    file = str(count) + ".csv"
    with open(file, 'wb') as output:
        writer = csv.writer(output)
        for index, row in reqs.iterrows():
            temp = str(row["headers"])
            temp = temp[10:]
            x = str(row[0][7:]) + str(temp.split("\"")[0])
            if x not in norepeats:
                     #first party, third party, id
                     writer.writerow([row[0][7:], temp.split("\"")[0], pers])
                     norepeats[x] = ""
            

