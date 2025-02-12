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

def AddKey(block1, block2):
    block3 = [['00']* 4 for j in range(4)]
    for row in range (0, 4):
        for col in range (0, 4):
            block3[row][col] = hex(block1[row][col] ^ block2[row][col])
    return(block3)
    print("Done with AddKey")

def SubBytes():
    print("Done with SubBytes")

def ShiftRows():
    print("Done with ShiftRows")

def MixColumns():
    print("Done with MixColumns")

def encryption(plaintext, subkeyFile):
    # Take the plaintext and convert it all into hex, then put in a list
    plaintextBytes = [ord(i) for i in list(plaintext)]
    # Create a list to keep track of all of the bytes we have
    plaintextBlocks = []
    # Create a 2d list for each block with each block being 16 bytes
    for i in range (0, (len(plaintextBytes) + 15) // 16):
        # Creates a 4 x 4 2d array with '00' for padding
        plaintextBlocks.append([['00']* 4 for j in range(4)])
        for j in range (0, 4):
            for k in range (0, 4):
                if len(plaintextBytes) > 0:
                    plaintextBlocks[i][j][k] = plaintextBytes.pop(0)
    with subkeyFile as file:
        subkeys = [line.rstrip() for line in file]
    subkeyBytes = []
    for i in range (0, len(subkeys)):
        bytes = [int((subkeys[i][j:j+2]), 16) for j in range(0, len(subkeys[i]), 2)]
        subkeyBytes.append(bytes)
    subkeyBlocks = []
    for i in range (0, len(subkeyBytes)):
        subkeyBlocks.append([['00']* 4 for j in range(4)])
        for j in range (0, 4):
            for k in range (0, 4):
                if len(subkeyBytes[i]) > 0:
                    subkeyBlocks[i][j][k] = subkeyBytes[i].pop(0)
    # We now have arrays of 4x4 blocks for the plaintext and subkeys
    print("Done with encryption")

encryption(plaintextFile.read(), subkeyFile)
