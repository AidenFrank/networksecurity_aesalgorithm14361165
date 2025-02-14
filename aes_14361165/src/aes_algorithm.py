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

try:
    sboxFile = open("aes_14361165\\data\\sbox.txt", "r")
except:
    print("No sbox file found! Please provide one in aes_14361165\\data\\ directory and named sbox.txt.")
    print("File should be a comma seperated list of hex values.")
    sys.exit()
else:
    print("Using sbox file: " + sboxFile.name)
    sbox = sboxFile.read().split(',')
    sboxASCII = []
    for i in sbox:
        sboxASCII.append(chr(int(i, 0)))

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

def SubBytes(block1):
    # Create a block to hold the computed data
    block2 = [[0]* 4 for j in range(4)]
    for row in range (0, 4):
        for col in range (0, 4):
            # Get the location we need to go to based on the hex
            lookup = list(format(block1[row][col], "02x"))
            # We split up the location into two parts, the first part of the hex for the row and the second part for the column
            location = int(lookup[0], 16) * 16 + int(lookup[1], 16)
            # Go to the location in sbox and append it to block2
            block2[row][col] = ord(sboxASCII[location])
    return(block2)

def ShiftRows(block1):
    # Create a block to hold the computed data
    block2 = [[0]* 4 for j in range(4)]
    # We shift each row left by n, the number of the row (first row shifts zero, second shifts 1, etc.)
    # TODO: Make this an actual algorithm
    for x in range (0, 4):
        block2[x][0] = block1[x][0]
    block2[0][1] = block1[1][1]
    block2[1][1] = block1[2][1]
    block2[2][1] = block1[3][1]
    block2[3][1] = block1[0][1]
    block2[0][2] = block1[2][2]
    block2[1][2] = block1[3][2]
    block2[2][2] = block1[0][2]
    block2[3][2] = block1[1][2]
    block2[0][3] = block1[3][3]
    block2[1][3] = block1[0][3]
    block2[2][3] = block1[1][3]
    block2[3][3] = block1[2][3]
    return(block2)

def MixColumns(block1):
    # We define our matrices, and format block1 correctly
    mixColumnMatrix = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
    fixedBlock1 = [[0]* 4 for j in range(4)]
    for row in range(0, 4):
        for col in range(0, 4):
            fixedBlock1[col][row] = block1[row][col]
    # We perform matrix multiplication
    block2 = [[0]* 4 for j in range(4)]
    '''
    for i in range(0, 4):
        for j in range(0, 4):
            for k in range(0, 4):
                block2[i][j] += mixColumnMatrix[i][k] * fixedBlock1[k][j]
    '''
    print("Done with MixColumns")

def Round(block, subkeyblock):
    subBytesBlock = SubBytes(block)
    shiftRowsBlock = ShiftRows(subBytesBlock)
    mixColumnsBlock = MixColumns(shiftRowsBlock)
    print("Done with Round")

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
    # We perform the initial transformation, AddKey with subkey 0
    initialTrans = AddKey(plaintextBlocks[0], subkeyBlocks[0])
    # We perform the first round
    round1 = Round(initialTrans, subkeyBlocks[1])
    print("Done with encryption")

encryption(plaintextFile.read(), subkeyFile)
