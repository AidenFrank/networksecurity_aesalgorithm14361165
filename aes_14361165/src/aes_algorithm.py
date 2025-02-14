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

# This function is used to print a block received as a 4 x 4 list of ASCII
def PrintBlock(block):
    print("Plain:")
    for col in range (0, 4):
        for row in range (0, 4):
            print(chr(block[row][col]), end=" ")
        print(" ")
    print("ASCII:")
    for col in range (0, 4):
        for row in range (0, 4):
            print(block[row][col], end=" ")
        print(" ")
    print("HEX:")
    for col in range (0, 4):
        for row in range (0, 4):
            print(format(block[row][col], "02x"), end=" ")
        print(" ")
            
# This performs an AddKey opertion on two blocks of 4 x 4 lists
def AddKey(block1, block2):
    # Create a block to hold the computed data
    block3 = [['00']* 4 for j in range(4)]
    for row in range (0, 4):
        for col in range (0, 4):
            # The data is in ACII, we use ^ to XOR it
            block3[row][col] = block1[row][col] ^ block2[row][col]
    return(block3)

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
                # While the plaintextBytes still has values, add them to plaintextBlocks
                if len(plaintextBytes) > 0:
                    plaintextBlocks[i][j][k] = plaintextBytes.pop(0)
    # We format the subkeys in the same manner, using 4 x 4 lists
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
    PrintBlock(AddKey(plaintextBlocks[0], subkeyBlocks[0]))
    print("Done with encryption")

encryption(plaintextFile.read(), subkeyFile)
