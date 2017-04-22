import hashlib
import base64
import zlib
import mmh3


identifiers = ["chester",
"Chester",
"Chestnut",
"OTHER identifiers"
]

hashedIDs = []

for ids in identifiers:
    hashedIDs.append(ids)


for ids in identifiers:
    string = ids

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

    hashedIDs.append(md5_string)
    hashedIDs.append(sha1_string)
    hashedIDs.append(sha256_string)
    hashedIDs.append(sha224_string)
    hashedIDs.append(sha384_string)
    hashedIDs.append(sha512_string)
    hashedIDs.append(b64_string)
    hashedIDs.append(crc32_string)
    hashedIDs.append(adler32_string)
    hashedIDs.append(mmh3_string)
    hashedIDs.append(mmh3_64_string_2)
    hashedIDs.append(mmh3_64_string_1)
    hashedIDs.append(mmh3_128_string)


print hashedIDs


