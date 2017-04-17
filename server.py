#!/usr/bin/python2.7
import sys, socket, json, argparse, threading, csv, ConfigParser,getpass
from base64 import b64encode
from Utility.crypto import *

dictionary = {} #For storing username and password
clientdict = {} #Client dictionary for client details
onlineuser = {} #List of online users


def create_socket(port):
    #Handle any exception generated while creating a socket
    try:
        udpsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #For non blocking sockets
        udpsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        #Bind the socket to a fixed port
        udpsocket.bind(("", port))
        return udpsocket
    except socket.error, msg:
        #display the error message
        print "Error Code : " + str(msg[0]) + " " + str(msg[1])
        sys.exit(0)

def functionality(client):
    while True:
        client_data, client_address = client.recvfrom(4096)
        try:
            data = json.loads(client_data.decode())
            if data.get('Request') == 'Hi' :
                puzzle = int(binascii.hexlify(os.urandom(16)),16)
                part_session = puzzle/1000
                data_to_send = {'ResponseTo':'Hi',
                                'Body':(generate_hash(str(puzzle)))+ str(part_session)}
                clientdict.update({client_address:{'puzzle':puzzle}})
                client.sendto(json.dumps(data_to_send),client_address)
            elif data.get('Request') == 'PuzzleResponse' :
                puzzle_response = int(data.get('puzzle'))
                if clientdict.get(client_address).get('puzzle') == puzzle_response:
                    keyAndUsername = rsa_decrypt(str(data.get('Body').decode('base-64')),private_key)
                    if keyAndUsername == -1:
                        print "Invalid Request!"
                        if clientdict.has_key(client_address):
                            del clientdict[client_address]
                        continue
                    else:
                        aeskey = keyAndUsername[0:32]
                        username = keyAndUsername[32:]
                        if dictionary.has_key(username):
                            session_id = int(binascii.hexlify(os.urandom(16)),16)
                            g,p = generate_dh_keys()
                            plaintext = json.dumps({'g': g, 'p':p,'session_id':session_id}).encode('base-64')
                            associated_data = os.urandom(16)
                            data_to_send = {'ResponseTo':'PuzzleResponse','Header':'1',
                                        'Body':str(aes_encrypt(aeskey, plaintext, associated_data).encode('base-64'))}
                            clientdict.update({client_address:{'username':username,'session_id':session_id,'g':g,'p':p}})
                            client.sendto(json.dumps(data_to_send),client_address)
                        else :
                            plaintext = "Authentication Failure!"
                            associated_data = os.urandom(16)
                            data_to_send = {'ResponseTo':'Error','Header':'1',
                                        'Body':str(aes_encrypt(aeskey, plaintext, associated_data).encode('base-64'))}
                            client.sendto(json.dumps(data_to_send),client_address)
                            del clientdict[client_address]

            elif data.get('Request') == 'Session' :
                session_id_response = data.get('session_id')
                if generate_hash(str(clientdict.get(client_address).get('session_id'))) == session_id_response:
                    if data.get('Header') == '1':
                            cipher = data.get('Body').decode('base-64')
                            iv = cipher[0:16]
                            tag = cipher[16:32]
                            associated_data = cipher[32:48]
                            ciphertext = cipher[48:]
                            response = aes_decrypt(aeskey, associated_data, iv, ciphertext, tag)
                            if response == -1:
                                print "Invalid Request!"
                                if clientdict.has_key(client_address):
                                    del clientdict[client_address]
                                continue
                            else:
                                response = json.loads(response.decode('base-64'))
                                gPowerA = int(response.get('gPowerA'))
                                b = int(binascii.hexlify(os.urandom(40)),16)
                                U = int(binascii.hexlify(os.urandom(16)),16)
                                C1 = int(binascii.hexlify(os.urandom(16)),16)
                                username = clientdict.get(client_address).get('username')
                                password = dictionary.get(username)[0]
                                W = int(binascii.hexlify(password),16)
                                g = clientdict.get(client_address).get('g')
                                p = clientdict.get(client_address).get('p')
                                plaintext = json.dumps({'SRP': pow(g,b,p) + pow(g,U*W,p),'session_id':clientdict.get(client_address).get('session_id'),
                                                                                                                        'C1':C1,'U':U}).encode('base-64')
                                client_server_key = pow(gPowerA,b,p)*pow(g,b*U*W,p)
                                client_server_session_key = generate_hash(str(client_server_key))[0:32]
                                associated_data = os.urandom(16)
                                data_to_send = {'ResponseTo':'Session','Header':'1',
                                                'Body':str(aes_encrypt(aeskey, plaintext, associated_data).encode('base-64'))}
                                client.sendto(json.dumps(data_to_send),client_address)
                                clientdict.update({client_address:{'username':username,
                                    'client_server_session_key':client_server_session_key,'C1':C1,'session_id':
                                                                                                    clientdict.get(client_address).get('session_id')}})
                    elif data.get('Header') == '2':
                            cipher = data.get('Body').decode('base-64')
                            iv = cipher[0:16]
                            tag = cipher[16:32]
                            associated_data = cipher[32:48]
                            ciphertext = cipher[48:]
                            client_server_session_key = clientdict.get(client_address).get('client_server_session_key')
                            response = aes_decrypt(client_server_session_key[0:32], associated_data, iv, ciphertext, tag)
                            if response != -1:
                                response = json.loads(response.decode('base-64'))
                                response_to_C1 = response.get('response_to_C1')
                                C1 = clientdict.get(client_address).get('C1')
                                if response_to_C1 != C1-1:
                                    plaintext = "Authentication Failure!"
                                    associated_data = os.urandom(16)
                                    data_to_send = {'ResponseTo':'Error','session_id':session_id,'Header':'1',
                                            'Body':str(aes_encrypt(aeskey, plaintext, associated_data).encode('base-64'))}
                                    client.sendto(json.dumps(data_to_send),client_address)
                                else :
                                    C2 = response.get('C2')
                                    client_public_key_pem = response.get('client_public_key_pem')
                                    client_public_key = serialization.load_pem_public_key(str(client_public_key_pem), backend=default_backend())
                                    plaintext = json.dumps({'response_to_C2':C2-1,'session_id':clientdict.get(client_address).get('session_id')}).encode('base-64')
                                    associated_data = os.urandom(16)
                                    data_to_send = {'ResponseTo':'Session','Header':'2',
                                                    'Body':str(aes_encrypt(client_server_session_key[0:32], plaintext, associated_data).encode('base-64'))}
                                    client.sendto(json.dumps(data_to_send),client_address)
                                    username = clientdict.get(client_address).get('username')
                                    client_public_key_pem = response.get('client_public_key_pem')
                                    clientdict.update({client_address:{'username':username,'client_server_session_key':client_server_session_key,
                                        'session_id':clientdict.get(client_address).get('session_id'),'client_public_key_pem':client_public_key_pem}})
                                    if onlineuser.has_key(username):
                                        dup_address = onlineuser.get(username)
                                        plaintext = "duplicate session"
                                        associated_data = os.urandom(16)
                                        client_server_session_key = clientdict.get(dup_address).get('client_server_session_key')
                                        data_to_send = {'ResponseTo':'Info','Header':'7',
                                                            'Body':str(aes_encrypt(client_server_session_key[0:32], plaintext, associated_data).encode('base-64'))}
                                        client.sendto(json.dumps(data_to_send),dup_address)
                                        del clientdict[dup_address]

                                    onlineuser.update({username:client_address})
                            else :
                                plaintext = "Authentication Failure!"
                                associated_data = os.urandom(16)
                                data_to_send = {'ResponseTo':'Error','Header':'1',
                                            'Body':str(aes_encrypt(aeskey, plaintext, associated_data).encode('base-64'))}
                                client.sendto(json.dumps(data_to_send),client_address)
                                if clientdict.has_key(client_address):
                                    del clientdict[client_address]

                    else :
                        plaintext = "Authentication Failure!"
                        associated_data = os.urandom(16)
                        data_to_send = {'ResponseTo':'Error','Header':'1',
                                    'Body':str(aes_encrypt(aeskey, plaintext, associated_data).encode('base-64'))}
                        client.sendto(json.dumps(data_to_send),client_address)
                        if clientdict.has_key(client_address):
                            del clientdict[client_address]
                else :
                        plaintext = "Authentication Failure!"
                        associated_data = os.urandom(16)
                        data_to_send = {'ResponseTo':'Error','Header':'1',
                                    'Body':'Authentication Failed!'}
                        client.sendto(json.dumps(data_to_send),client_address)
                        if clientdict.has_key(client_address):
                            del clientdict[client_address]
            elif data.get('Request') == 'Info' :
                session_id_response = data.get('session_id')
                if generate_hash(str(clientdict.get(client_address).get('session_id'))) == session_id_response:
                    cipher = data.get('Body').decode('base-64')
                    iv = cipher[0:16]
                    tag = cipher[16:32]
                    associated_data = cipher[32:48]
                    ciphertext = cipher[48:]
                    client_server_session_key = clientdict.get(client_address).get('client_server_session_key')
                    command = str(aes_decrypt(client_server_session_key[0:32], associated_data, iv, ciphertext, tag))
                    if command == '-1':
                        print "Invalid Request!"
                        if clientdict.has_key(client_address):
                            del clientdict[client_address]
                        continue
                    else:
                        command = command.split()
                        if command[0] == 'list':
                            plaintext = json.dumps({'list':onlineuser.keys(),'session_id':clientdict.get(client_address).get('session_id')})
                            associated_data = os.urandom(16)
                            data_to_send = {'ResponseTo':'Info','Header':'1',
                                            'Body':str(aes_encrypt(client_server_session_key[0:32], str(plaintext), associated_data).encode('base-64'))}
                            client.sendto(json.dumps(data_to_send),client_address)
                        elif command[0] == 'send':
                            if dictionary.has_key(command[1]):
                                if onlineuser.has_key(command[1]):
                                    g,p = generate_dh_keys()
                                    client1_public_key = clientdict.get(client_address).get('client_public_key_pem')
                                    client1_server_session_key = clientdict.get(client_address).get('client_server_session_key')
                                    client2_public_key = clientdict.get(onlineuser.get(command[1])).get('client_public_key_pem')
                                    client2_address = onlineuser.get(command[1])
                                    client2_server_session_key = clientdict.get(onlineuser.get(command[1])).get('client_server_session_key')
                                    plaintext_1 = {'client_username':command[1],'client_address':client2_address, 'g':g, 'p':p, 
                                                        'client_public_key_pem':client2_public_key,'session_id':clientdict.get(client_address).get('session_id')}
                                    plaintext_1 = json.dumps(plaintext_1) 
                                    plaintext_2 = {'client_username':clientdict.get(client_address).get('username'), 'client_address':client_address, 'g':g, 
                                    'p':p, 'client_public_key_pem':client1_public_key,'session_id':clientdict.get(onlineuser.get(command[1])).get('session_id')} 
                                    plaintext_2 = json.dumps(plaintext_2)
                                    data_to_client1 = {'ResponseTo':'Info','Header':'2',
                                                'Body':str(aes_encrypt(client1_server_session_key[0:32], str(plaintext_1), associated_data).encode('base-64'))}
                                    data_to_client2 = {'ResponseTo':'Info','Header':'3',
                                                'Body':str(aes_encrypt(client2_server_session_key[0:32], str(plaintext_2), associated_data).encode('base-64'))}
                                    client.sendto(json.dumps(data_to_client1),client_address)
                                    client.sendto(json.dumps(data_to_client2),client2_address)
                                else:
                                    plaintext = "User is not Online"
                                    associated_data = os.urandom(16)
                                    data_to_send = {'ResponseTo':'Info','Header':'6',
                                                'Body':str(aes_encrypt(client_server_session_key, plaintext, associated_data).encode('base-64'))}
                                    client.sendto(json.dumps(data_to_send),client_address)
                            else :
                                plaintext = "User Doesn't Exists"
                                associated_data = os.urandom(16)
                                data_to_send = {'ResponseTo':'Info','Header':'6',
                                            'Body':str(aes_encrypt(client_server_session_key, plaintext, associated_data).encode('base-64'))}
                                client.sendto(json.dumps(data_to_send),client_address)

                        elif command[0] == 'logout':
                            plaintext = 'OK'
                            associated_data = os.urandom(16)
                            client_server_session_key = clientdict.get(client_address).get('client_server_session_key')
                            data_to_send = {'ResponseTo':'Info','Header':'4',
                                                'Body':str(aes_encrypt(client_server_session_key, plaintext, associated_data).encode('base-64'))}
                            client.sendto(json.dumps(data_to_send),client_address)
                            logout_request = {'username':clientdict.get(client_address).get('username'),'message':'logout'}
                            del onlineuser[clientdict.get(client_address).get('username')]
                            logout_request = json.dumps(logout_request)
                            for i in onlineuser.values():
                                client_server_session_key = clientdict.get(tuple(i)).get('client_server_session_key')
                                data_to_send = {'ResponseTo':'Info','Header':'5',
                                                'Body':str(aes_encrypt(client_server_session_key, logout_request, associated_data).encode('base-64'))}
                                client.sendto(json.dumps(data_to_send),tuple(i))


                else :
                    plaintext = "Authentication Failure!"
                    associated_data = os.urandom(16)
                    data_to_send = {'ResponseTo':'Error','Header':'1',
                                'Body':str(aes_encrypt(client_server_session_key, plaintext, associated_data).encode('base-64'))}
                    client.sendto(json.dumps(data_to_send),client_address)
                    if clientdict.has_key(client_address):
                        del clientdict[client_address]

            else :
                pass
        except:
            pass

def command_interface(udpsocket):
    #just initialise message variable so that code can go into while loop
    message = 'Initialize'
    while message!='quit':
        message = raw_input("+>")
        try:
            if message == 'quit':
                break
            elif message == 'register':
                username = raw_input('Username:')
                while dictionary.get(username):
                    username = raw_input('This username is already been taken.\nPlease enter a different username.\n')
                password = generate_hash(getpass.getpass('Password:'))
                dictionary.update({username:[password,]})
                with open(user_file, 'a') as csvfile:
                    file = csv.writer(csvfile, delimiter=',')
                    file.writerow([username,password])
                csvfile.close()
            elif message == 'login':
                username = raw_input('Username:')
                password = generate_hash(getpass.getpass('Password:'))
                if dictionary.get(username):
                    if password == dictionary.get(username)[0]:
                        print "Login try success"
            else:
                print "Commands supported : \nquit\nregister"
        except:
            pass

    #close the udp socket.
    udpsocket.close()
    os._exit(0)

#This is the main function which spawns a thread for listening and sending data to clients
def main():
    config = ConfigParser.RawConfigParser()
    config.read('Server/server.cfg')
    global user_file
    user_file = config.get('passwords', 'filename')
    #create the socket using the function
    udpSocket = create_socket(config.getint('my_address', 'port'))
    private_key_file = config.get('server_keys', 'private_key')
    global private_key 
    private_key = load_private_key(private_key_file)

    with open(user_file, 'rb') as csvfile:
        file = csv.reader(csvfile, delimiter=',')
        for row in file:
            if row!=[]:
                dictionary.update({row[0]:[row[1]]})
    
    os.system('cls' if os.name == 'nt' else 'clear')
    print "Server Initialized..."

    #spawn a thread to handle connections and sending data to clients
    manage_clients = threading.Thread(target=functionality, args=(udpSocket,))
    manage_clients.setDaemon(True)
    manage_clients.start()
    manage_input = threading.Thread(target=command_interface, args=(udpSocket,))
    manage_input.setDaemon(True)
    manage_input.start()
    manage_input.join()
    manage_clients.join()


#the main boilerplate
if __name__=='__main__':
    #to handle keyboard exceptions
    try:
        main()
    except KeyboardInterrupt:
        print "Exiting the program...\nBYE!!!"