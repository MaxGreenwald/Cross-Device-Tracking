from libmproxy import flow
import sys, operator
from collections import Counter


##this takes a mitmproxy flow (version 0.14) and finds all identifiers taken by each 3rd party and puts them into a csv file
##the csv file is organized by third party, identifers taken (and if hashed or not), number of PII taken, list of hash types used


## text file of identifiers
ids = ['chester', 'other ids', 'md5 hash of chester','other hashes']
numIdentifiers = 18
hashDict = ["md5", "sha1", "sha256", "sha224", "sha384", "sha512", "b64", "crc32", "adler32", "mmh3", "mmh3-64-1", "mmh3-64-2", "mmh3-128"]
numHashes = 13
database = {}
hashDatabase = {}

#open the flow and read each packet
arg2 = sys.argv[1]
with open(arg2, "rb") as logfile:
    freader = flow.FlowReader(logfile)
    try:
        for f in freader.stream():

            host = f.request.pretty_host(hostheader=True)

            for id in ids:
                try:
                    if id in f.request.content or id in f.request.headers or id in f.request.url or id in f.response.headers:
                        plaintextID = id
                        if ids.index(id) >= numIdentifiers: ##is this a plaintext or hashed identifier
                            plaintextID = ids[(ids.index(id) - numIdentifiers) / numIdentifiers]
                            hashType = hashDict[(ids.index(id) - numIdentifiers) % numHashes]
                            plaintextID = hashType + " hash of " + plaintextID
                        else:
                            plaintextID = id
                            hashType = ""
                        if host in database:
                            if plaintextID not in database[host]:
                                database[host].append(plaintextID)
                        else:
                            database[host] = [plaintextID]

                        if hashType != "":
                            #print hashType
                            if host in hashDatabase and hashType not in hashDatabase[host]:
                                hashDatabase[host].append(hashType)
                            else:
                                hashDatabase[host] = [hashType]
                        elif host not in hashDatabase:
                            hashDatabase[host] = [""]
                except AttributeError:
                    continue

                    print "found " + plaintextID + " in " + host

                f.request.pretty_host(hostheader=True)
            #print f.response.content
    except flow.FlowReadError as v:
        print "Flow file corrupted. Stopped loading."

print database

for data in database:
   print data + " takes " + str(len(database[data])) + " identifiers from the app " + str(arg2)

import csv
file = arg2[12:-4] + ".csv"
print "finishing for:"
print file

with open(file, 'wb') as output:
    writer = csv.writer(output)
    for key, value in database.iteritems():
        writer.writerow([key, value, str(len(value)), hashDatabase[key]])