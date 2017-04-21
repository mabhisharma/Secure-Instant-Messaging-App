## Prerequisites
python 2.7
cryptography
install using:
```bash
sudo apt-get install build-essential libssl-dev libffi-dev python-dev
pip install cryptography
```

## Configuration
Server config: ./Server/server.cfg
```
[server_keys]
private_key = Server/Keys/server_private_key.pem
public_key = Server/Keys/server_public_key.der

[passwords]
filename = Server/username.csv

[my_address]
ip_address = 127.0.0.1
port = 5555
```
Client config: ./Cilent/client.cfg
```
[server_keys]
public_key = Client/Keys/server_public_key.der

[server_address]
ip_address = 127.0.0.1
port = 5555
```
## Run
### Server
Run server:
```
python server.py
```
Exit prorgram:
```
Server Initialized...
+>quit
```
Add user and its hash to Server/username.csv
```
+>register
Username:test
Password:
+>
```
Already added usernames and passwords -
```
USERNAME       PASSWORD
Alice          alicepwd1@#         
Bob            BobDbui1der!@#     
Carol          ohhcarol&^%          
Dan            theCave!@#$    
Eve            dontjudg3m3#@!
Frank          imnotFr@nk!
Grace          plsgiveussome!!!
```

### Client
Run client:
```
python client.py
```
Enter username and password:
```
Username:test0
Password:
Ready to chat :)
```
List online users:
```
list
List of online users -
1. Eve
2. Carol
3. Frank
4. Bob
5. Grace
6. Dan
7. Alice
```
Send messages:
```
send Alice hello
Me : hello
```
Exit client:
```
quit
Logging out from the system
```
