import sys

# We have two possible inputs for the script: plaintext file and subkey file
# If a file is not provided, we default to the ones provided in the data folder
try:
    plaintextFile = open(sys.argv[1], "r")
except IndexError:
    print("No plaintext file specified. Defaulting to aes_14361165\\data\\plaintext.txt")
    plaintextFile = open("aes_14361165\\data\\plaintext.txt", "r")
else:
    print("Using plaintext file: " + plaintextFile.name)

try:
    subkeyFile = open(sys.argv[2], "r")
except IndexError:
    print("No subkey file specified. Defaulting to aes_14361165\\data\\subkey_example.txt")
    subkeyFile = open("aes_14361165\\data\\subkey_example.txt", "r")
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
    # Create a list to keep track of all of the bytes we have
    blocks = []
    # Create a 2d list for each block with each block being 16 bytes
    for i in range (0, (len(bytes) + 15) // 16):
        # Creates a 4 x 4 2d array with '00' for padding
        blocks.append([['00']* 4 for j in range(4)])
        for j in range (0, 4):
            for k in range (0, 4):
                if len(bytes) > 0:
                    blocks[i][j][k] = bytes.pop(0)
    
    print("Done with encryption")

encryption(plaintextFile.read(), subkeyFile.read())
