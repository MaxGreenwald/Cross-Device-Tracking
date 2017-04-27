from libmproxy import flow
import sys, operator
from collections import Counter


## text file of identifiers
ids = ['chester', 'Chester', 'Chestnut', 'chestnut', 'chestermchestnut@outlook.com', 'OUchester!', '10.9.132.81', '365816905f5e9c148e20273719fe163d', '5c9688a59f3fcbfdbfeea06378a76af06a09aa95', 'a384e2f868dbe2347844d303784dfc82b39dd32d40e322f8941e20c1775846da', '67bbcf4f04e0269b7eb58491f82036fc2dbeb0230c810c8eb6dda517', '9c208368a7daffca8095e8a60d4532780a3e19525df3ec80f57c92f63c3c63336662ed20087a8bafc3bd35f18b9a7362', '30e3d9dae348456b1e8564a812012d73a200913198813ed2bcbe362c60810ccf2de764efd6b3b279b1e1187f767d6e67c31f86664186bbf26f3e424b355db5be', 'Y2hlc3Rlcg==', '515161088', '193528559', '-1253064931', '-8122826525384327151', '-6176440144542524577', '190442664852034377868268570986870512479', '2074fbf44ff6179f59b43c491cc06b62', '3abb594d47b2541d1adb2252f104f083b9ea6f26', '618738f7143c9b43a98a6b42d743a6595069a9b4dcf42d7deafb725d1e93dd52', 'c64cf1d76512e56016db208fb31fe282e20614b153d2161907a4c39b', '5ae2cd4076ffee9b76f33875a9a48cf2f89f94e0e59b0fb88a442ce6c48b2c2445625a9d61428d31de2b6435abfb52bd', 'a739277dd5caa8ca9a3234732ffc76f3a7250e324b10f458ab535e8b4c951da1d6c6fb32b23ec6fcbcf1c8f282bce93d4a3ea366e80a412ed82b1fc32723f12f', 'Q2hlc3Rlcg==', '-787905124', '178848463', '2055844952', '4439507851761708713', '-8915048649156571756', '81894465154672322789879112337783410068', '98f2d2794c75ac86f8c89296dcbd5592', 'c712b8835755410091fbe89cfba2f9989bcdddf1', '9512f4afb8279641f13bf88ac2111dbddb586239968ddafe6b63980a266eaaae', 'bb2f7b693329e5559fe22edd11439abbbf3fbe8052e863083dce00f9', 'f64cd28b13f12bdf8a2c4cfe97a1ffa44c40e80d92b00c7c10ec98c1d86375127a3e97918e7f7a3ed3bd64937f75e378', '99a7bfd2b712edbe7a4246ac65935b2ac879d70d6ed1cbba912e145abf7de666ab5f5e78e77129c77267acd4b6eba92ab21c748fe09761870edd41626f93b4fe', 'Q2hlc3RudXQ=', '1058469220', '235733839', '1886452799', '-2300898194569560537', '-2685163309951992751', '297838286786053415824808426891087592529', 'eeb5777ea0f6ee22e8bc44303799ba9f', '7e1617ee6b3486fe443d325c374c547c567f79e7', '06d92f17a33b28585d90927b2226c4bd8eb0985ffdc41036b2e6cf6106289181', '93ab2b4a69555e3438461cad73064b953c77d416f2eb9909db83909f', 'cd727a5587bb7642d1aee5a95a30bd0d0cd7cef5f4903366ce3fe541a8edd00de009454979f57002c1fc05b5656c265f', 'fffdda7b22e759fbde77ab5771af6fcf19f05b2f77e6ed578e03154f0ab8f7d120da9f94f70d551348ba9766b59c8dc2b8d70591f474774e123a18462145df59', 'Y2hlc3RudXQ=', '-966748366', '252511087', '1073799239', '5065040019922786249', '7180532355284949082', '93433496970612366494808069710485477466', 'ebaa910f1ad21ccc979fa6b6b8efe76e', '6a4f69d84aabc089d9fb3e7a9a67dd0ebf956d6e', 'd8ad6e238c1de38d4622ad9902bd88707841835a1d36c57de30933c732b605df', '382e35a353561277f21ebc7bdba1f54ccc7b48ea6854665f3f203e87', '3ae4bb397d18d52668ffada85fcf08610ebe3140199e79cb7d30490c007639e8cf6e9c2682e6f94622895252fe391626', 'a74bd5f8ab1561a3810a481c7c8828854c62116c1cf517f55699e3b91575c5c5514e6d96b30f501b8f2b0e542061d7a3c64102bf203ca46a6b02b2c429167970', 'Y2hlc3Rlcm1jaGVzdG51dEBvdXRsb29rLmNvbQ==', '-1481334560', '-1460466812', '-2104108014', '-1943131701459691942', '316538335611784677', '304437913722599733445325232025071717861', 'f84615d693c48261bae37d8540ecef11', '9caafefb843657267d72999228c0eebbf77c0ec8', '1f37187fc821948678cb67ab572cf689286501e7e9d42792cce1acc1c4e8b025', 'dd593631ef140fca35add3fb6376ff002ec9d00476feed63c1518a90', '7cd39b2d5b131b3f9a168e2aacc333f914167e32345aabf6fbc8974855df2467e4e0d2e679884f662fe65af966ccc5bf', '51e6cb847b84cee33990e7c8a6806826abba0e309a74061fdb7e458acfefe931de0bd5e05c528c0673b0f4a983e4b763e36c8c37f176b0ed3402092236c50051', 'T1VjaGVzdGVyIQ==', '1336517732', '346948532', '-944111982', '-6931682040116073143', '-3309336161898063679', '212415402326588356802679747378389850305', '4370eb952e8dfc20b76afc4fa8e61e8d', '3bc5d43aeccd878e289329939dccb50416ce43b4', 'cd078b04ac6099fae4a2d94f17697f77a82b717bcd35acdb70da8f3d69c9e962', 'f2be0c2c5a20e05ab1db337f96f588e5a21aefb38b83b585b4211b06', 'e28f6173d971b2e6928acf38e752ddb8def15fd056a1262214acc13b6c847bdff0b75f3368201d3fafb8ed37e0317f99', '0e36a518fe4cd5dbe187df9a0c2ed592c03ce3ee10712b08d59ab8d222070124ef5b960b2f2aab210ac162778e56fc07560ab7814be3ec61f1511d0f1019d140', 'MTAuOS4xMzIuODE=', '-1565260303', '214303268', '-810067368', '-6363409023186412856', '-4259921399023118509', '222898189233884615396341526907236669267']
numIdentifiers = 7
hashDict = ["md5", "sha1", "sha256", "sha224", "sha384", "sha512", "b64", "crc32", "adler32", "mmh3", "mmh3-64-1", "mmh3-64-2", "mmh3-128"]
numHashes = 13
database = {}

#open the flow and read each packet
arg2 = sys.argv[1]
with open(arg2, "rb") as logfile:
    freader = flow.FlowReader(logfile)
    try:
        for f in freader.stream():
            #print "headers"
            #print f.response.content[0:100]
            #print "content"

            host = f.request.pretty_host(hostheader=True)

            for id in ids:
                if id in f.request.content or id in f.request.headers or id in f.request.url or id in f.response.headers:
                    plaintextID = id
                    if ids.index(id) >= numIdentifiers: ##is this a plaintext or hashed identifier
                        plaintextID = ids[(ids.index(id) - numIdentifiers) / numIdentifiers]
                        hashType = hashDict[(ids.index(id) - numIdentifiers) % numHashes]
                        plaintextID = hashType + " hash of " + plaintextID
                    else:
                        plaintextID = id
                    if host in database:
                        database[host].append(plaintextID)
                    else:
                        database[host] = [plaintextID]

                    print "found " + plaintextID + " in " + host


                #f.response.content ... maybe check this if I wont get false positives, need to filter out site itself and perhaps cdns

                # elif id in f.request.url:
                #     print "in url"
                # elif id in f.request.headers:
                #     print "in headers"
                # elif id in f.response.content:
                #     print "found in resp cont"
                # elif id in f.response.headers:
                #     print "in resp head"

                f.request.pretty_host(hostheader=True)
            #print f.response.content
    except flow.FlowReadError as v:
        print "Flow file corrupted. Stopped loading."

print database

for data in database:
    print data + " takes " + str(len(database[data])) + " identifiers from the app " + str(arg2)


###
### flow.response.headers
### flow.response.path