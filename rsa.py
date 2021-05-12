import random, sys, math
from hashlib import sha512

SYMBOLS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890 !?.'

#main
def main():
     # Create a public/private keypair with 1024-bit keys:
     actions()

# generate key files        
def makeKeyFiles(name):
    
    publicKey, privateKey = generateKeys()

    print()
    # print('The public key is a %s and a %s digit number.' % (len(str(publicKey[0])), len(str(publicKey[1]))))
    print('Writing public key to file %s_pubkey.txt...' % (name))
    fo = open('%s_pubkey.txt' % (name), 'w')
    fo.write('%s,%s,%s' % (1024, publicKey[0], publicKey[1]))
    fo.close()
    print()
    # print('The private key is a %s and a %s digit number.' %
    # (len(str(publicKey[0])), len(str(publicKey[1]))))
    print('Writing private key to file %s_privkey.txt...' % (name))
    fo = open('%s_privkey.txt' % (name), 'w')
    fo.write('%s,%s,%s' % (1024, privateKey[0], privateKey[1]))
    fo.close()
    
    return publicKey,privateKey

    # If makePublicPrivateKeys.py is run (instead of imported as a module),
    # call the main() function:

#generate keys
def generateKeys():
    # Creates public/private keys keySize bits in size.
    print('*** Generating p and q prime ***\n')

    p = nBitRandom()
    q = nBitRandom()

    # p = 7933446547184891278736631349216727883148850801367578425852402291221056403030704915537888887469930922490202386226352485147508812792051673699222161285696807
    # q = 7277358666725147053526412436572926274152964709709708849847122677951554729454391722411077466676470956481759690145352570529643099018161311345448184462906911
  
    p_rabin = rabinMiller(p)
    q_rabin = rabinMiller(q)

    flag = True
   
    if(p_rabin == True and q_rabin == False):
        while flag :
            q = nBitRandom()
            if(rabinMiller(q) ==True and p!=q):
                flag =False
    elif((p_rabin== False and q_rabin==True)):
        while flag:
            p = nBitRandom()
            if(rabinMiller(p) ==True and p!=q):
               flag =False
    elif(p_rabin== False and q_rabin==False):
        while flag:
            p = nBitRandom()
            q=  nBitRandom()
            if(rabinMiller(p) ==True and rabinMiller(q) == True and p!=q):
               flag =False
            
    n = p * q

    print('p: ',p)
    print('')
    print('q: ', q)
    print('')

    print('*** Calculating (n = p * q) ***')
    print('')
    print('n:',n)

    print('')
    
    # Step 2: Create a number e that is relatively prime to (p-1)*(q-1):
    print('*** Generating "e" that is relatively prime to (p-1)*(q-1) *** \n')
    while True:
        # Keep trying random numbers for e until one is valid:
        e = random.randrange(2 ** (1024 - 1), 2 ** (1024))
        if gcd(e, (p - 1) * (q - 1)) == 1:
            break

    print('e: ',e,'\n')

    # Step 3: Calculate d, the mod inverse of e:
    print('*** Calculating "d" that is mod inverse of "e" ***\n')
    d = findModInverse(e, (p - 1) * (q - 1))

    print('d: ',d)
    print('')
    

    print('*** Public and Private Keys ***\n')
    publicKey = (n, e)
    privateKey = (n, d)
    print('Public key:', publicKey)
    print('')
    print('Private key:',privateKey)

    return (privateKey, publicKey)

# returns a random number between 2**(n-1)+1 and 2**n-1
def nBitRandom(n=512):
  
    # Returns a random number
    # between 2**(n-1)+1 and 2**n-1'''
    return(random.randrange(2**(n-1)+1, 2**n-1))
       
#use Rabin-Miller algorithm to return True (n is probably prime) or False (n is definitely composite)
def rabinMiller(n, k = 40):
   if n < 6:  # assuming n >= 0 in all cases... shortcut small cases here
      return [False, False, True, True, False, True][n]
   elif n & 1 == 0:  # should be faster than n % 2
      return False
   else:
      s, d = 0, n - 1
      while d & 1 == 0:
         s, d = s + 1, d >> 1
      # Use random.randint(2, n-2) for very large numbers
      for a in random.sample(range(2, min(n - 2,sys.maxsize)), min(n - 4, k)):
         x = pow(a, d, n)
         if x != 1 and x + 1 != n:
            for r in range(1, s):
               x = pow(x, 2, n)
               if x != 1:
                  return False  # composite for sure
               elif x !=- 1:
                  break  # could be strong liar, try another a
            else:
               return False  # composite if we reached end of this loop
      return True  # probably prime if reached end of outer loop     

# calculates gdc
def gcd(a, b):
    # Return the GCD of a and b using Euclid's Algorithm
    while a != 0:
        a, b = b % a, a
    return b

# calculates mod inverse
def findModInverse(a, m):
    # Returns the modular inverse of a % m, which is
    # the number x such that a*x % m = 1

    if gcd(a, m) != 1:
        return None # no mod inverse if a & m aren't relatively prime

    # Calculate using the Extended Euclidean Algorithm:
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3 # // is the integer division operator
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m

# menu
def actions():        
        fileName = 'encrypted_file.txt'
        pubKeyFile = 'RSA_pubkey.txt'
        privKeyFile = 'RSA_privkey.txt'
    
        privateKey, publicKey = makeKeyFiles('RSA')
        
        #Message
        message = input("\nWhat would you like to be encrypted?:")
        print("Your message is:",message,'\n')

        #sign message
        hash = int.from_bytes(sha512(message.encode()).digest(), byteorder='big')
        signature = pow(hash,privateKey[1], privateKey[0])
        print("Signature:", hex(signature))
        print('')

        enc_msg = encryptAndWriteToFile(fileName,pubKeyFile,message)
        print("Your encrypted message is:",enc_msg)

        # RSA verify signature
        hash = int.from_bytes(sha512(message.encode()).digest(), byteorder='big')
        hashFromSignature = pow(signature, publicKey[1], publicKey[0])
        if(hash == hashFromSignature):
            print('')
            print("Signature valid!\n")
            print(hex(hash),'=',hex(hashFromSignature))
            print('')

            privKeyFilename = 'RSA_privkey.txt' 
            print('Reading from %s and decrypting...' % (fileName)) 
            decryptedText = readFromFileAndDecrypt(fileName, privKeyFile)
            print("Your decrypted message is:",decryptedText)

        elif(hash != hashFromSignature):
            print("Signature invalid!\n")
            print(hex(hash),'!=',hex(hashFromSignature))

        print('')
        input('Press ENTER to quit RSA program...')

# read key files 
def readKeyFile(keyFilename):  
    # Given the filename of a file that contains a public or private key, 
    # return the key as a (n,e) or (n,d) tuple value. 
    fo = open(keyFilename)
    content = fo.read()
    fo.close()
    keySize, n, EorD = content.split(',')     
    return (int(keySize), int(n), int(EorD)) 

# encrypt message and write to a file
def encryptAndWriteToFile(messageFilename, keyFilename, message,blockSize=None):
    # Using a key from a key file, encrypt the message and save it to a106.     
    # # file. Returns the encrypted message string.    
    keySize, n, e = readKeyFile(keyFilename)
    if blockSize == None:
        # If blockSize isn't given, set it to the largest size allowed by the key size and symbol set size.
        blockSize = int(math.log(2 ** keySize, len(SYMBOLS)))
    if not (math.log(2 ** keySize, len(SYMBOLS)) >= blockSize):
        sys.exit('ERROR: Block size is too large for the key and symbolset size. Did you specify the correct key file and encrypted file?')
    
    # Encrypt the message:
    encryptedBlocks = encryptMessage(message, (n, e), blockSize)
    
    # Convert the large int values to one string value:
    for i in range(len(encryptedBlocks)):
        encryptedBlocks[i] = str(encryptedBlocks[i])
    
    encryptedContent = ','.join(encryptedBlocks)
    
    #Write out the encrypted string to the output file
    encryptedContent = '%s_%s_%s' % (len(message), blockSize,encryptedContent)
    fo = open(messageFilename, 'w')
    fo.write(encryptedContent)
    fo.close()
    # Also return the encrypted string:
    return encryptedContent

# encrypt message
def encryptMessage(message, key, blockSize): 
    # Converts the message string into a list of block integers, and then 
    # encrypts each block integer. Pass the PUBLIC key to encrypt. 
    encryptedBlocks = [] 
    n, e = key
    for block in getBlocksFromText(message, blockSize): 
        # ciphertext = plaintext ^ e mod n 
        encryptedBlocks.append(pow(block, e, n)) 
        return encryptedBlocks

# encode text
def getBlocksFromText(message, blockSize): 
    # Converts a string message to a list of block integers. 
    for character in message: 
        if character not in SYMBOLS: 
            print('ERROR: The symbol set does not have the character %s' % (character)) 
            sys.exit() 
    blockInts = [] 
    for blockStart in range(0, len(message), blockSize): 
        # Calculate the block integer for this block of text: 
        blockInt = 0 
        for i in range(blockStart, min(blockStart + blockSize,len(message))): 
             blockInt += (SYMBOLS.index(message[i])) * (len(SYMBOLS) ** (i % blockSize)) 
        blockInts.append(blockInt) 
    return blockInts

# read cipher and decrypt message
def readFromFileAndDecrypt(messageFilename, keyFilename):
        # Using a key from a key file, read an encrypted message from a file
        # and then decrypt it. Returns the decrypted message string.
        keySize, n, d = readKeyFile(keyFilename)
    
        # Read in the message length and the encrypted message from the file:
        fo = open(messageFilename)
        content = fo.read()
        
        messageLength, blockSize, encryptedMessage = content.split('_')
        messageLength = int(messageLength)
        blockSize = int(blockSize)
        
        # Check that key size is large enough for the block size:
        if not (math.log(2 ** keySize, len(SYMBOLS)) >= blockSize):
            sys.exit('ERROR: Block size is too large for the key and symbol set size. Did you specify the correct key file and encrypted file?')
     
        # Convert the encrypted message into large int values:
        encryptedBlocks = []
        for block in encryptedMessage.split(','):
            encryptedBlocks.append(int(block))

        # Decrypt the large int values:
        return decryptMessage(encryptedBlocks, messageLength, (n,d),blockSize)

# decrypt message
def decryptMessage(encryptedBlocks, messageLength, key, blockSize):
    decryptedBlocks = []
    n, d = key
    for block in encryptedBlocks:
        # plaintext = ciphertext ^ d mod n
        decryptedBlocks.append(pow(block, d, n))
    return getTextFromBlocks(decryptedBlocks, messageLength, blockSize)

# decode file
def getTextFromBlocks(blockInts, messageLength, blockSize):
    message = []
    for blockInt in blockInts:
          blockMessage = []
          for i in range(blockSize - 1, -1, -1):
              if len(message) + i < messageLength:
                charIndex = blockInt // (len(SYMBOLS) ** i)
                blockInt = blockInt % (len(SYMBOLS) ** i)
                blockMessage.insert(0,SYMBOLS[charIndex])
          message.extend(blockMessage)
    return ''.join(message)

if __name__ == '__main__':
        main()