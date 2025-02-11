import sys

# We have two possible inputs for the script: plaintext file and subkey file
# If a file is not provided, we default to the ones provided in the data folder
try:
    plaintextFile = open(sys.argv[1], "r")
except IndexError:
    print("No plaintext file specified. Defaulting to data\\plaintext.txt")
    plaintextFile = open("data\\plaintext.txt", "r")
else:
    print("Using plaintext file: " + plaintextFile.name)

try:
    subkeyFile = open(sys.argv[2], "r")
except IndexError:
    print("No subkey file specified. Defaulting to data\\subkey_example.txt")
    subkeyFile = open("data\\subkey_example.txt", "r")
else:
    print("Using subkey file: " + subkeyFile.name)

def AddKey():
    print("Done with AddKey")

def SubBytes():
    print("Done with SubBytes")

def ShiftRows():
    print("Done with ShiftRows")

def MixColumns():
    print("Done with MixColumns")

def encryption(plaintext, subkey):
    # Take the plaintext and convert it all into hex, then put in a list
    bytes = [i.encode("utf-8").hex() for i in list(plaintext)]
    # Create a list to keep track of all of the bytearrays we have
    blocks = []
    print(bytes)
    # Add to blocks while bytes still has values
    while bytes:
        bytearray = [['00']*4]*4
        for i in range(16):
            bytearray[i % 4][1] = bytes.pop(0)
        print(bytearray)
    
    print("Done with encryption")

encryption(plaintextFile.read(), subkeyFile.read())
