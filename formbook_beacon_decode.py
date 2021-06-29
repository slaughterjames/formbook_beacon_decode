#! /usr/bin/env python3
'''
Formbook Beacon Decode
Author: James Slaughter
Elements of code derived from: https://github.com/ThisIsSecurity/malware/blob/master/formbook/formbook_decode_pcap.py
Purpose: The aim of this code is to demonstrate a grasp of how the Formbook communications protocol works using their GET beacon 
'''

#python import
import sys
import os
import base64
import binascii
import struct
from collections import OrderedDict
from Crypto.Hash import SHA
from Crypto.Cipher import ARC4
from datetime import date

#programmer generated imports
from controller import controller

'''
Usage()
Function: Display the usage parameters when called
'''
def Usage():
    print ('Usage: [required] --uribase --getline [optional] --debug --help')
    print ('Example: ./formbook_beacon_decode.py --uribase www.lacrr.com/heye/ --getline "?L6AhA=8pjPf8&2dpxt=GFQnpj5ffe8gY1X5lngk8QUCYAfzued70SqtlWYIs8y3Vsj/B2JRdADq6w1S4saTOaiYK7slCLk0d4k=" --debug')
    print ('Required Arguments:')
    print ('--uribase - domain + uri')
    print ('--getline - Line being decoded')
    print ('Optional Arguments:')
    print ('--debug - Prints verbose logging to the screen to troubleshoot issues with a recon installation.')
    print ('--help - You\'re looking at it!')
    sys.exit(-1)
            
'''
Parse() - Parses program arguments
'''
def Parse(args):        
    option = ''

    print ('[*] Length Arguments: ' + str(len(args)))

    if (len(args) == 1):
        return -1

    print ('[*] Arguments: ')
    for i in range(len(args)):
        if args[i].startswith('--'):
            option = args[i][2:]
                
            if option == 'help':
                return -1

            if option == 'uribase':
                CON.uribase = args[i+1]
                print (option + ': ' + CON.uribase)                              

            if option == 'getline':
                CON.getline = args[i+1]
                print (option + ': ' + CON.getline)
                
            if option == 'debug':
                CON.debug = True
                print (option + ': ' + str(CON.debug))               
                                     
    #These are required params so length needs to be checked after all 
    #are read through         
    if (len(CON.getline) < 3):
        print ('[x] getline is a required argument.')
        print ('')
        return -1

    if (len(CON.uribase) < 3):
        print ('[x] uribase is a required argument.')
        print ('')
        return -1

    print ('')   
    
    return 0

'''
sha1_revert()
Function: - Returns our RC4 Hash
'''
def sha1_revert(digest):

    #The SHA1 has for whatever reason has been constructed in such a way that the endian-ness has been reversed,
    #so we have to go through this rigamarole to then arrive at the RC4 key
    if (CON.debug == True):
        print ('[DEBUG] SHA1 Digest: ' + str(digest)) #as binary
    tuples = struct.unpack("<IIIII", digest) #Unpacks binary data
    output_hash = bytes()
    for item in tuples:
        output_hash += struct.pack(">I", item)
    return output_hash

'''
Execute()
Function: - Does the doing against a string
'''
def Execute():

    sha1 = SHA.new()
    sha1.update(CON.uribase.encode('utf-8'))
    rc4_key = sha1_revert(sha1.digest())

    if (CON.debug == True):
        print ('[DEBUG] rc4_key: ' + str(rc4_key))

    params = CON.getline.split('&')
    for p in params:  # The line is structured in such a way that the arguments we're interested in could be ordered a different way each time
       key, value = p.split('=', 1)
       if (CON.debug == True):
           print ('[DEBUG] Key: ' + str(key))
           print ('[DEBUG] Value: ' + str(value))
       try:
           #Let's decode once.
           encrypted = base64.b64decode(value)
           if (CON.debug == True):
               print ('[DEBUG] Encrypted: ' + str(encrypted))
           decrypted = ARC4.new(rc4_key).decrypt(encrypted)
           if (CON.debug == True):
               print ('[DEBUG] Decrypted: ' + str(decrypted)) 
           if decrypted.startswith(b'FBNG'):
               print ('Decrypted String: ' + str(decrypted))
               data = str(decrypted, 'utf-8')
               args = data.split(':')
               if len(args) >= 4:
                   magic = args[0] # FBNG are the "magic" bytes that ID this as interesting traffic
                   print ('username: ' + str(base64.b64decode(args[3]), 'utf-8')) #For whatever reason, the username is still base64 encoded after decrypting
                   print ('sid_crc: ' + args[1][:8])
                   print ('version: ' + args[1][8:])
                   print ('windows_version: ' + args[2])
       except binascii.Error:  # fake args are not base64 compliant so ignore
           pass
    return 0

'''
Terminate()
Function: - Attempts to exit the program cleanly when called  
'''
     
def Terminate(exitcode):
    sys.exit(exitcode)

'''
This is the mainline section of the program and makes calls to the 
various other sections of the code
'''

if __name__ == '__main__':
    
    ret = 0

    #Stores our args
    CON = controller()
                   
    #Parses our args
    ret = Parse(sys.argv)

    #Something bad happened
    if (ret == -1):
        Usage()
        Terminate(ret)

    #Do the doing
    Execute()

    print ('')
    print ('[*] Program Complete')

    Terminate(0)
'''
END OF LINE
'''

