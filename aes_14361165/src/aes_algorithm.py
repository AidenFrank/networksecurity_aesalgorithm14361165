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
    return block2

# Used to multiply two hex values together
def HexMultiplication(a, b):
    # a * 1 is just a, so return a
    if b == 1:
        return a
    # Perform a left shift
    c = (a << 1) & 0xff
    if b == 2:
        if a < 128:
            return c
        else:
            return c ^ 0x1b
    if b == 3:
        return HexMultiplication(a, 2) ^ a

def MixColumns(block1):
    # We define our matrix for multiplication
    mixColumnMatrix = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
    # We perform matrix multiplication
    block2 = [[]* 4 for j in range(4)]
    for mulRow in range(0, 4):
        for row in range(0, 4):
            result = 0x00
            for col in range(0, 4):
                result = result ^ HexMultiplication(block1[mulRow][col], mixColumnMatrix[row][col])
            block2[mulRow].append(result)
    return block2

# This goes through all of the steps of a round of AES
def Round(block, subkeyblock):
    subBytesBlock = SubBytes(block)
    shiftRowsBlock = ShiftRows(subBytesBlock)
    mixColumnsBlock = MixColumns(shiftRowsBlock)
    addKeyBlock = AddKey(mixColumnsBlock, subkeyblock)
    return addKeyBlock

# This just prints a block as a hex
def PrintHex(block):
    result = "0x"
    for row in range(0, 4):
        for col in range(0, 4):
            result += format(block[row][col], "02x")
    print(result)

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
    # We perform the first round with our initial transformation and subkey 1
    round1 = Round(initialTrans, subkeyBlocks[1])
    # We print the first round output
    print("Round 1 output:")
    PrintHex(round1)

encryption(plaintextFile.read(), subkeyFile)
