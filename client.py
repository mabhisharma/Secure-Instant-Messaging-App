#!/usr/bin/python2.7
import os, sys, socket, json, argparse, threading, csv, getpass,time, ConfigParser
from base64 import b64encode
from Queue import Queue
from Utility.crypto import *

q = Queue()
clientdict = {}
clientusernamedict ={}


def rsa_decrypt(cipher,private_key):
    if len(cipher) > 256:
        x = len(cipher)/256
        plain = ''
        for i in range(1,x+1):
            ciphertext = cipher[(i-1)*256:i*256]
            plaintext = private_key.decrypt(ciphertext,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA512()),algorithm=hashes.SHA256(),label=None))
            plain += str(plaintext)
    else :
        plaintext = private_key.decrypt(cipher,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA512()),algorithm=hashes.SHA256(),label=None))
        return plaintext
    return plain

def authenticate_with_server(udpSocket,server,username,W,server_public_key):
    #print "sending HI request!!"
    data_to_send = {'Request': 'Hi'}
    udpSocket.sendto(json.dumps(data_to_send).encode(), server)
    session_id = -1
    while True:
        receivedData,server_address = udpSocket.recvfrom(4096)
        data = json.loads(receivedData.rstrip().decode())
        if data.get('ResponseTo') == 'Hi' :
            bhash = data.get('Body')[0:90]
            part_puzzle = str(data.get('Body')[90:])
            for i in range(0,999):
                puzzle = part_puzzle + str(i)
                if bhash == generate_hash(puzzle):
                    break
                else :
                    puzzle = -1
            if puzzle == -1:
                return 0,0,0,0
            aeskey = os.urandom(32)
            body = {'aeskey:'}
            data_to_send = {'Request':'PuzzleResponse','puzzle':puzzle,'Header':'1',
                            'Body':str(rsa_encrypt(str(aeskey+username),server_public_key).encode('base-64'))}
            udpSocket.sendto(json.dumps(data_to_send).encode(), server)
        elif data.get('ResponseTo') == 'PuzzleResponse' :
            cipher = data.get('Body').decode('base-64')
            iv = cipher[0:16]
            tag = cipher[16:32]
            associated_data = cipher[32:48]
            ciphertext = cipher[48:]
            response = aes_decrypt(aeskey, associated_data, iv, ciphertext, tag)
            if response == -1:
                print style[1]+"Problem Detected.\nExiting!!!"+ style[0]
                os._exit(0)
            response = json.loads(response.decode('base-64'))
            g = int(response.get('g'))
            p = int(response.get('p'))
            session_id = int(response.get('session_id'))
            a = int(binascii.hexlify(os.urandom(40)),16)
            gPowerA = pow(g,a,p)
            plaintext = json.dumps({'gPowerA': gPowerA}).encode('base-64')
            associated_data = os.urandom(16)
            data_to_send = {'Request':'Session','session_id':generate_hash(str(session_id)),'Header':'1',
                                'Body':str(aes_encrypt(aeskey, str(plaintext), associated_data).encode('base-64'))}
            udpSocket.sendto(json.dumps(data_to_send).encode(), server)
        elif data.get('ResponseTo') == 'Session' :
            if int(session_id):
                if data.get('Header') == '1':
                    cipher = data.get('Body').decode('base-64')
                    iv = cipher[0:16]
                    tag = cipher[16:32]
                    associated_data = cipher[32:48]
                    ciphertext = cipher[48:]
                    response = aes_decrypt(aeskey, associated_data, iv, ciphertext, tag)
                    if response == -1:
                        print style[1]+"Problem Detected.\nExiting!!!"+ style[0]
                        os._exit(0)
                    response = json.loads(response.decode('base-64'))
                    if plaintext != -1:
                        if session_id == response.get('session_id'):
                            U = int(response.get('U'))
                            C1 = int(response.get('C1'))
                            SRP = int(response.get('SRP'))
                            W = int(binascii.hexlify(W),16)
                            gPowerB = SRP - pow(g,U*W,p)
                            C2 = int(binascii.hexlify(os.urandom(16)),16)
                            client_server_key = pow(gPowerB,a,p)*pow(gPowerB,U*W,p)
                            client_server_session_key = generate_hash(str(client_server_key))[0:32]
                            own_private_key,own_public_key = generate_rsa_keys()
                            own_public_key_pem = own_public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo)
                            plaintext = json.dumps({'response_to_C1': C1-1,'C2':C2,'client_public_key_pem':own_public_key_pem}).encode('base-64')
                            associated_data = os.urandom(16)
                            data_to_send = {'Request':'Session','session_id':generate_hash(str(session_id)),'Header':'2',
                                                 'Body':str(aes_encrypt(client_server_session_key[0:32], str(plaintext), associated_data).encode('base-64'))}
                            udpSocket.sendto(json.dumps(data_to_send).encode(), server)
                        else:
                            return 0,0,0,0

                    else :
                        return 0,0,0,0

                elif data.get('Header') == '2':
                    cipher = data.get('Body').decode('base-64')
                    iv = cipher[0:16]
                    tag = cipher[16:32]
                    associated_data = cipher[32:48]
                    ciphertext = cipher[48:]
                    response = aes_decrypt(client_server_session_key[0:32], associated_data, iv, ciphertext, tag)
                    if response == -1:
                        print style[1]+"Problem Detected.\nExiting!!!"+ style[0]
                        os._exit(0)
                    response = json.loads(response.decode('base-64'))
                    if plaintext!= -1:
                        if session_id == response.get('session_id'):
                            associated_data = os.urandom(16)
                            response_to_C2 = response.get('response_to_C2')
                            if response_to_C2 != C2-1:
                                print style[1] + "Error While Authetication" + style_default
                                plaintext = "Authentication Failure!"
                                associated_data = os.urandom(16)
                                data_to_send = {'ResponseTo':'Error','session_id':session_id,'Header':'1',
                                        'Body':str(aes_encrypt(aeskey, plaintext, associated_data).encode('base-64'))}
                                return 0,0,0,0,0,0,0,0
                        
                        return session_id,client_server_session_key[0:32],own_private_key,own_public_key
                    else :
                        return 0,0,0,0
        elif data.get('ResponseTo') == 'Error':
            cipher = data.get('Body').decode('base-64')
            iv = cipher[0:16]
            tag = cipher[16:32]
            associated_data = cipher[32:48]
            ciphertext = cipher[48:]
            plaintext = aes_decrypt(aeskey, associated_data, iv, ciphertext, tag)
            if plaintext == -1:
                print style[1]+"Problem Detected.\nExiting!!!"+ style[0]
                os._exit(0)
            return 0,0,0,0

def set_session_with_client(client_username,username,udpSocket, own_private_key):
    client_address = clientdict.get(client_username).get('client_address')
    client_public_key_pem = clientdict.get(client_username).get('client_public_key_pem')
    client_public_key = serialization.load_pem_public_key(str(client_public_key_pem), backend=default_backend())
    C1 = int(binascii.hexlify(os.urandom(16)),16)
    a = int(binascii.hexlify(os.urandom(40)),16)
    g = clientdict.get(client_username).get('g')
    p = clientdict.get(client_username).get('p')
    gPowerA = pow(g,a,p)
    plaintext = json.dumps({'username': username, 'C1':C1,'gPowerA':gPowerA})
    data_to_send = {'Request':'Client','Header':'1',
                            'Body':str(rsa_encrypt(str(plaintext),client_public_key).encode('base-64'))}
    udpSocket.sendto(json.dumps(data_to_send).encode(), client_address)
    wait_time = 0.125
    time.sleep(wait_time)
    while (q.empty() and wait_time <1):
        wait_time = wait_time*2
        time.sleep(wait_time)
        pass
    if wait_time == 1:
        return -1
    recievedData = q.get()
    cipher = rsa_decrypt(str(recievedData),own_private_key)
    if cipher != -1 :
        data = json.loads(cipher)
        if client_username == data.get('username'):
            response_to_C1 = data.get('C1').decode('base-64')
            iv = response_to_C1[0:16]
            tag = response_to_C1[16:32]
            associated_data = response_to_C1[32:48]
            ciphertext = str(response_to_C1[48:])
            C2 = data.get('C2')
            gPowerB = data.get('gPowerB')
            sharedKey = str(pow(gPowerB,a,p))[0:32]
            if (C1-1) == int(aes_decrypt(sharedKey, associated_data, iv, ciphertext, tag)):
                clientdict.update({client_username:{'sharedKey' : sharedKey,'client_address':client_address,
                                                                                'client_session_id': data.get('client_session_id')}})
                data_to_send = {'Request':'Client','Header':'3','client_session_id':generate_hash(str(data.get('client_session_id'))),
                                'Body':aes_encrypt(sharedKey,str(C2-1),associated_data).encode('base-64')}
                udpSocket.sendto(json.dumps(data_to_send).encode(),client_address)
                return 1
            else :
                print style[1] + "Authetication failed with client" + style_default
                return -1
        else :
            print style[1] + "Authetication failed with client" + style_default
            return -1
    else:
        return -1
def command_interface(udpSocket,server,session_id,client_server_session_key,own_private_key,username):
    print style[0] + "Ready to chat :)" + style_default
    while True:
        try :
            message = raw_input(style[0])
            #take user input
            message = message.split()

            #If the user requests LIST then request to the server
            if message[0] == 'list':
                #print "inside List"
                plaintext = 'list'
                associated_data = os.urandom(16)
                data_to_send = {'Request':'Info','session_id':generate_hash(str(session_id)),'Header':'1',
                                         'Body':str(aes_encrypt(client_server_session_key, str(plaintext), associated_data).encode('base-64'))}
                udpSocket.sendto(json.dumps(data_to_send).encode(), server)
                wait_time = 0.125
                time.sleep(wait_time)
                while (q.empty() and wait_time <1):
                    wait_time = wait_time*2
                    time.sleep(wait_time)
                    pass
                if wait_time == 1:
                    print style[1]+"Unable to connect to the server.\nPlease quit and try again later!"
                    continue
                recievedData = q.get()
                #print "Data received"
                server_data = json.loads(recievedData)
                #print the list of Users signed in the server
                cipher = server_data.get('Body').decode('base-64')
                iv = cipher[0:16]
                tag = cipher[16:32]
                associated_data = cipher[32:48]
                ciphertext = cipher[48:]
                response = aes_decrypt(client_server_session_key[0:32], associated_data, iv, ciphertext, tag)
                if response == -1:
                    print style[1]+"Problem Detected.\nExiting!!!"+ style[0]
                    os._exit(0)
                response = json.loads(response)
                if session_id == response.get('session_id'):
                    print style[4]+"List of online users -"
                    count = 0
                    for i in response.get('list'):
                        count +=1
                        if i == username:
                            print style[0]+str(count)+ ". "+ i+style[4]
                            pass
                        else :
                            print str(count)+". "+ i
                else :
                    print style[1] + "Error" + style_default

            elif message[0]=='send':
                try:
                    if len(message) > 2:
                        plaintext = 'send' +' '+str(message[1])
                        if message[1] == username :
                            print style[0] + "Me" + " : "+''.join(message[2:]) + style_default
                        elif message[1] in clientdict:
                            if clientdict.get(message[1]).has_key('sharedKey'):
                                sharedKey = clientdict.get(message[1]).get('sharedKey')
                                plaintext = " ".join(message[2:])
                                client_session_id = clientdict.get(message[1]).get('client_session_id')
                                associated_data = os.urandom(16)
                                data_to_send = {'Request':'Data','Header':'1','client_session_id':generate_hash(str(client_session_id)),
                                                 'Body':str(aes_encrypt(sharedKey, str(plaintext), associated_data).encode('base-64'))}
                                udpSocket.sendto(json.dumps(data_to_send).encode(), tuple(clientdict.get(message[1]).get('client_address')))
                            else :
                                value = set_session_with_client(message[1],username,udpSocket,own_private_key)
                                if value == 1:
                                    client_session_id  = clientdict.get(message[1]).get('client_session_id')
                                    sharedKey = clientdict.get(message[1]).get('sharedKey')
                                    plaintext = " ".join(message[2:])
                                    associated_data = os.urandom(16)
                                    data_to_send = {'Request':'Data','Header':'1','client_session_id':generate_hash(str(client_session_id)),
                                                     'Body':str(aes_encrypt(sharedKey, str(plaintext), associated_data).encode('base-64'))}
                                    udpSocket.sendto(json.dumps(data_to_send).encode(), tuple(clientdict.get(message[1]).get('client_address')))
                                    
                        else :
                            associated_data = os.urandom(16)
                            data_to_send = {'Request':'Info','session_id':generate_hash(str(session_id)),'Header':'2',
                                                 'Body':str(aes_encrypt(client_server_session_key, str(plaintext), associated_data).encode('base-64'))}
                            udpSocket.sendto(json.dumps(data_to_send).encode(), server)
                            #wait as the other thread recieves the data and sets the recivedData variable
                            wait_time = 0.125
                            time.sleep(wait_time)
                            while (q.empty() and wait_time <1):
                                wait_time = wait_time*2
                                time.sleep(wait_time)
                                pass
                            if wait_time == 1:
                                print style[1]+"Unable to connect to the server.\nPlease quit and try again later!"
                                continue
                            recievedData = q.get()
                            if str(recievedData) == "User Doesn't Exists":
                                print style[1] + recievedData + style_default
                            elif str(recievedData) == "User is not Online":
                                print style[1] + recievedData + style_default
                            else:
                                clientdict.update(recievedData)
                                value = set_session_with_client(message[1],username,udpSocket,own_private_key)
                                if value == 1:
                                    client_session_id  = clientdict.get(message[1]).get('client_session_id')
                                    sharedKey = clientdict.get(message[1]).get('sharedKey')
                                    plaintext = " ".join(message[2:])
                                    associated_data = os.urandom(16)
                                    data_to_send = {'Request':'Data','Header':'1','client_session_id': generate_hash(str(client_session_id)),
                                                     'Body':str(aes_encrypt(sharedKey, str(plaintext), associated_data).encode('base-64'))}
                                    udpSocket.sendto(json.dumps(data_to_send).encode(), tuple(clientdict.get(message[1]).get('client_address')))
                                else :
                                    print style[1] + "Unable to send data to the user" + style_default
                    else:
                        print style[1] + "usage of send: <send username message>" + style[0]
                except :
                    print style[1] + "usage of send: <send username message>" + style[0]

            elif message[0]=='quit':
                plaintext = 'logout'
                associated_data = os.urandom(16)
                data_to_send = {'Request':'Info','session_id':generate_hash(str(session_id)),'Header':'3',
                                     'Body':str(aes_encrypt(client_server_session_key, str(plaintext), associated_data).encode('base-64'))}
                udpSocket.sendto(json.dumps(data_to_send).encode(), server)
                wait_time = 0.125
                time.sleep(wait_time)
                while (q.empty() and wait_time <1):
                    wait_time = wait_time*2
                    time.sleep(wait_time)
                    pass
                if wait_time == 1:
                    print style[1]+"Unable to connect to the server.\nSo logging you out of the system!"
                    os._exit(0)
                response = q.get()
                if response == 'OK':
                    print "Logging out from the system"
                    os._exit(0)

                
            else:
                #when unknown command is received
                print "Sorry no such command found"
                print "Commands available - list, send, quit "
        except :
            pass
    print "BYE!!!"
    udpSocket.close()

#This function receives the data from other clients and server
#Also the passed the data to the main thread
def receivingdata(udpSocket, server, session_id, client_server_session_key,own_private_key,username):
    while True:
        #receive the data
        server_data, server_address = udpSocket.recvfrom(4096)
        #if the data was sent by the main server then set the recievedData variable as it requires processing
        if server_address == server:
            data = json.loads(server_data.rstrip().decode())
            if data.get('ResponseTo') == 'Info' :
                if data.get('Header') == '1':
                    q.put(server_data.rstrip().decode())
                elif data.get('Header') == '2':
                    cipher = data.get('Body').decode('base-64')
                    iv = cipher[0:16]
                    tag = cipher[16:32]
                    associated_data = cipher[32:48]
                    ciphertext = cipher[48:]
                    response = json.loads(aes_decrypt(client_server_session_key[0:32], associated_data, iv, ciphertext, tag))
                    if response == -1:
                        continue
                    client_address = tuple(response.get('client_address'))
                    client_username = response.get('client_username') 
                    client_public_key_pem = response.get('client_public_key_pem')
                    g = response.get('g')
                    p = response.get('p')
                    data = {client_username:{'client_address':client_address,'g':g,'p':p,'client_public_key_pem':client_public_key_pem}}
                    clientusernamedict.update({client_address:client_username})
                    q.put(data)
                elif data.get('Header') == '3':
                    cipher = data.get('Body').decode('base-64')
                    iv = cipher[0:16]
                    tag = cipher[16:32]
                    associated_data = cipher[32:48]
                    ciphertext = cipher[48:]
                    response = json.loads(aes_decrypt(client_server_session_key[0:32], associated_data, iv, ciphertext, tag))
                    if response == -1:
                        continue
                    client_address = tuple(response.get('client_address'))
                    client_username = response.get('client_username') 
                    client_public_key_pem = response.get('client_public_key_pem')
                    g = response.get('g')
                    p = response.get('p')
                    data = {client_username:{'client_address':client_address,'g':g,'p':p,'client_public_key_pem':client_public_key_pem}}
                    clientdict.update(data)
                    clientusernamedict.update({client_address:client_username})
                elif data.get('Header') == '4':
                    cipher = data.get('Body').decode('base-64')
                    iv = cipher[0:16]
                    tag = cipher[16:32]
                    associated_data = cipher[32:48]
                    ciphertext = cipher[48:]
                    response = aes_decrypt(client_server_session_key, associated_data, iv, ciphertext, tag)
                    if response == '-1':
                        continue
                    q.put(response)
                elif data.get('Header') == '5':
                    cipher = data.get('Body').decode('base-64')
                    iv = cipher[0:16]
                    tag = cipher[16:32]
                    associated_data = cipher[32:48]
                    ciphertext = cipher[48:]
                    response = aes_decrypt(client_server_session_key, associated_data, iv, ciphertext, tag)
                    if response == -1:
                        continue
                    response = json.loads(response)
                    if response.get('message') == 'logout':
                        if clientdict.has_key(response.get('username')):
                            del clientdict[response.get('username')]
                            print style[1] + "User "+ response.get('username') + " is now offline" + style[0]
                        else :
                            pass
                elif data.get('Header') == '6':
                    cipher = data.get('Body').decode('base-64')
                    iv = cipher[0:16]
                    tag = cipher[16:32]
                    associated_data = cipher[32:48]
                    ciphertext = cipher[48:]
                    response = aes_decrypt(client_server_session_key, associated_data, iv, ciphertext, tag).rstrip()
                    if response == -1:
                        continue
                    q.put(response)
                elif data.get('Header') == '7':
                    cipher = data.get('Body').decode('base-64')
                    iv = cipher[0:16]
                    tag = cipher[16:32]
                    associated_data = cipher[32:48]
                    ciphertext = cipher[48:]
                    response = aes_decrypt(client_server_session_key, associated_data, iv, ciphertext, tag)
                    if response == -1:
                        continue
                    if response == "duplicate session":
                        print "Logging you out as duplicate session exists!"
                        os._exit(0)


        else :
            client_address = server_address
            data = json.loads(server_data.rstrip().decode())
            if data.get('Request') == 'Client' :
                if data.get('Header') == '1':
                    decrypt = rsa_decrypt(str(data.get('Body').decode('base-64')),own_private_key)
                    if decrypt == -1:
                        continue
                    data = json.loads(decrypt)
                    if clientdict.has_key(data.get('username')):
                        client_username = data.get('username')
                        C1 = int(data.get('C1'))
                        g = clientdict.get(client_username).get('g')
                        p = clientdict.get(client_username).get('p')
                        gPowerA = data.get('gPowerA')
                        b = int(binascii.hexlify(os.urandom(40)),16)
                        gPowerB = pow(g,b,p)
                        sharedKey = str(pow(gPowerA,b,p))[0:32]
                        associated_data = os.urandom(16)
                        C2 = int(binascii.hexlify(os.urandom(16)),16)
                        client_session_id = binascii.hexlify(os.urandom(16))
                        encrypted_C1 = aes_encrypt(sharedKey,str(C1-1),associated_data).encode('base-64')
                        message = json.dumps({'username':username,'C1':encrypted_C1,'gPowerB':gPowerB,'C2':C2,'client_session_id':client_session_id})
                        client_public_key_pem = clientdict.get(client_username).get('client_public_key_pem')
                        client_public_key = serialization.load_pem_public_key(str(client_public_key_pem), backend=default_backend())
                        data_to_send = {'Request':'Client','Header':'2',
                                    'Body':str(rsa_encrypt(message,client_public_key).encode('base-64'))}
                        client_address = clientdict.get(client_username).get('client_address')
                        udpSocket.sendto(json.dumps(data_to_send).encode(), client_address)
                        clientdict.update({client_username:{'client_public_key':client_public_key,
                            'sharedKey':sharedKey,'client_address':client_address,'client_session_id':client_session_id}})
                        clientusernamedict.update({client_address:client_username})
                elif data.get('Header') == '2':
                    cipher = data.get('Body').decode('base-64')
                    q.put(cipher)
                elif data.get('Header') == '3':
                    response_client_session_id = data.get('client_session_id')
                    client_username = clientusernamedict.get(client_address)
                    if clientdict.get(client_username).has_key('client_session_id'):
                        if generate_hash(clientdict.get(client_username).get('client_session_id').rstrip()) == response_client_session_id:
                            cipher = data.get('Body').decode('base-64')
                            iv = cipher[0:16]
                            tag = cipher[16:32]
                            associated_data = cipher[32:48]
                            ciphertext = cipher[48:]
                            sharedKey = clientdict.get(client_username).get('sharedKey')
                            client_session_id = clientdict.get(client_username).get('client_session_id')
                            response_to_C2 = aes_decrypt(sharedKey, associated_data, iv, ciphertext, tag)
                            if response_to_C2 == -1:
                                continue
                            if int(C2-1) == int(response_to_C2):
                                clientdict.update({client_username:{'sharedKey' : sharedKey,'client_address':client_address, 
                                                                                                'client_session_id':client_session_id}})
                            else :
                                print "Authentication Failed!"
                                del clientdict[client_username]
                        else :
                            print "Authentication Failed!"
                            del clientdict[client_username]

            elif data.get('Request') == 'Data':
                client_username = clientusernamedict.get(client_address)
                response_client_session_id = data.get('client_session_id')
                if generate_hash(str(clientdict.get(client_username).get('client_session_id'))) == response_client_session_id:
                    cipher = data.get('Body').decode('base-64')
                    iv = cipher[0:16]
                    tag = cipher[16:32]
                    associated_data = cipher[32:48]
                    ciphertext = cipher[48:]
                    sharedKey = clientdict.get(client_username).get('sharedKey')
                    data = aes_decrypt(sharedKey, associated_data, iv, ciphertext, tag)
                    if data == -1:
                        continue
                    print style[5] + client_username + " : " +str(data)+ style[0]
                else :
                    pass

def create_socket():
    #Handle any exception generated while creating a socket
    try:
        udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #For non blocking sockets
        udpSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        #Bind the socket to a fixed port
        return udpSocket
    except socket.error, msg:
        #display the error message
        print "Error Code : " + str(msg[0]) + " " + str(msg[1])
        os._exit(0)

#This is the main function
def main():
    config = ConfigParser.RawConfigParser()
    config.read('Client/client.cfg')
    server_public_key_file = config.get('server_keys', 'public_key')
    server = config.get('server_address','ip_address'), config.getint('server_address', 'port')
    os.system('cls' if os.name == 'nt' else 'clear')
    #create a udp socket
    udpSocket = create_socket()
    server_public_key = load_public_key(server_public_key_file)
    username = raw_input('Username:')
    password = generate_hash(getpass.getpass('Password:'))
    session_id,client_server_session_key,own_private_key,own_public_key = authenticate_with_server(udpSocket,
                                                                                    server,username,password,server_public_key)
    if int(session_id) == 0:
        print "Error while Authentication!!"
        os._exit(0)


    os.system('cls' if os.name == 'nt' else 'clear')
    manage_data = threading.Thread(target=receivingdata, args=(udpSocket,server,
                                                                 session_id,client_server_session_key,own_private_key,username))
    manage_data.setDaemon(True)
    manage_data.start()
    manage_input = threading.Thread(target=command_interface, args=(udpSocket,server,session_id,
                                                                            client_server_session_key,own_private_key,username))
    manage_input.setDaemon(True)
    manage_input.start()
    manage_input.join()
    manage_data.join()

#the main boilerplate
if __name__=='__main__':
    #to handle keyboard exceptions
    try:
        main()
    except KeyboardInterrupt:
        print "Exiting the program...\nBYE!!!"