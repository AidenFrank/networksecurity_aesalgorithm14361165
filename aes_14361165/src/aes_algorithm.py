import sys
import os
# We have two possible inputs for the script: plaintext file and subkey file
# If a file is not provided, we default to the ones provided in the data folder
try:
    plaintextFile = open(sys.argv[1], "r")
except IndexError:
    print("No plaintext file specified. Defaulting to aes_14361165\\data\\plaintext.txt")
    plaintextFile = open(os.path.abspath("aes_14361165/data/plaintext.txt"), "r")
else:
    print("Using plaintext file: " + plaintextFile.name)

try:
    subkeyFile = open(sys.argv[2], "r")
except IndexError:
    print("No subkey file specified. Defaulting to aes_14361165\\data\\subkey_example.txt")
    subkeyFile = open(os.path.abspath("aes_14361165/data/subkey_example.txt"), "r")
else:
    print("Using subkey file: " + subkeyFile.name)

try:
    sboxFile = open(os.path.abspath("aes_14361165/data/sbox.txt"), "r")
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

# This just converts a block as a hex
def ConvertHex(block):
    result = ""
    for row in range(0, 4):
        for col in range(0, 4):
            result += format(block[row][col], "02x")
    return(result)
            
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
    # The first row isn't shifted at all, so we just set it equal to our original values
    for x in range (0, 4):
        block2[x][0] = block1[x][0]
    # Now we just set each block value to the corresponding value it should be after shift
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

def LeftCircularShift(word):
    # We don't need any bitwise operations because our words are just lists of 4 bytes, so we just reassign the bytes
    tmp = []
    tmp.append(word[1])
    tmp.append(word[2])
    tmp.append(word[3])
    tmp.append(word[0])
    return(tmp)

# This goes through all of the steps of a round of AES
def Round(block, subkeyblock):
    subBytesBlock = SubBytes(block)
    shiftRowsBlock = ShiftRows(subBytesBlock)
    mixColumnsBlock = MixColumns(shiftRowsBlock)
    addKeyBlock = AddKey(mixColumnsBlock, subkeyblock)
    return addKeyBlock

def SubkeySchedule(previousSubkeyBlock, roundConstant):
    # We create a block to hold our words
    w = [[0]* 4 for j in range(4)]
    for row in range(0, 4):
        for col in range(0, 4):
            w[row][col] = previousSubkeyBlock[row][col]
    # We keep track of the original last word of the block and its hex value
    w3Original = []
    for i in range(0, 4):
        w3Original.append(w[3][i])
    w3OriginalHex = "0x"
    for i in range(0, 4):
        w3OriginalHex += format(w[3][i], "02x")
    # We perform g function on the last word in our block: Left Circular Shift, SubBytes, XOR with round constant
    w[3] = LeftCircularShift(w[3])
    w[3] = SubBytes([[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], w[3]])[3]
    w3Hex = "0x"
    for i in range(0, 4):
        w3Hex += format(w[3][i], "02x")
    w3Hex = int(w3Hex, 16) ^ roundConstant
    # We put the new last word back into the block
    for i in range(0, 4):
        w[3][i] = int(format(w3Hex, "02x")[i*2:(i*2+2)], 16)
    # We start formatting every word has a string of hex so that it can be XORed
    hexWords = []
    # Create y block to be used as the output of the function
    y = [[0]* 4 for j in range(4)]
    for i in range(0, 4):
        tmp = "0x"
        for j in range(0, 4):
            tmp += format(w[i][j], "02x")
        hexWords.append(tmp)
    # Now we use tmpWord to get the output of the XOR and then extract the hex values from it, convert to int
    # and put it into our y block
    tmpWord = format(int(hexWords[0], 16) ^ int(hexWords[3], 16), "02x")
    for i in range(0, 4):
        y[0][i] = int(tmpWord[i*2:(i*2+2)], 16)
    tmpWord = format(int(tmpWord, 16) ^ int(hexWords[1], 16), "02x")
    for i in range(0, 4):
        y[1][i] = int(tmpWord[i*2:(i*2+2)], 16)
    tmpWord = format(int(tmpWord, 16) ^ int(hexWords[2], 16), "02x")
    for i in range(0, 4):
        y[2][i] = int(tmpWord[i*2:(i*2+2)], 16)
    # Note that we XOR with the original last word of the w block
    tmpWord = format(int(tmpWord, 16) ^ int(w3OriginalHex, 16), "02x")
    for i in range(0, 4):
        y[3][i] = int(tmpWord[i*2:(i*2+2)], 16)
    return(y)

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
    # We use our initial subkey to get Subkey 1
    subkey1 = SubkeySchedule(subkeyBlocks[0], 0x01000000)
    print("Subkey 1:")
    print(ConvertHex(subkey1))
    # We perform the first round with our initial transformation and subkey 1
    round1 = Round(initialTrans, subkey1)
    # We print the first round output
    print("Round 1 output:")
    print(ConvertHex(round1))
    # Write the result of the first subkey to a file
    result_subkey = open(os.path.abspath("aes_14361165/data/result_subkey.txt"), "w")
    result_subkey.write(ConvertHex(subkey1))
    result_subkey.close()
    # Write the result of the first round to a file
    result = open(os.path.abspath("aes_14361165/data/result.txt"), "w")
    result.write(ConvertHex(round1))
    result.close()


encryption(plaintextFile.read(), subkeyFile)
