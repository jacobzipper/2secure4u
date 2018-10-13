# 2secure4u - TSFU

The TSFU protocol aims to fix most of the security issues with various protocols currently used

TSFU is designed to provide a secure guaranteed exchange between client/sender and server/receiver, and nullify possibility of data corruption

TSFU is NOT meant to be efficient or practical

### Issues with available protocols
* Ensuring client and server are actually communicating (avoiding man in the middle attacks (MITM))
	* HTTP (unencrypted protocols	in general)
		* Plaintext is dumb and bad don't do it a h4x0r doesn't even need to do anything to steal data
		* You can use asymmetric key encryption for data transmission, buttttttttttttt
			* No secure way of transmitting public key (attacker can modify/create a packet sending their public key)
	* SSL/TLS
		* Trusts certificate authority (CA) to sign server public key with their private key (this is good, butttttttttttt)
			* Attacker can pretend to be server and get their public key signed by CA with similar information
			* If you're super anal about security, you can check all the details of the certificate and check with an SSL certificate database to see if certificate exactly matches host you're attempting to reach, butttttttttt
				* No one actually does this
				* If the attacker can impersonate the server and mess with your packets, they could impersonate common certificate search services like sslshopper, certdb, etc and modify packets to "verify" the attacker's "authenticity"
				* You have serious trust/paranoia issues if you do this seek professional help please
* Ensuring authenticity and no corruption of data from the client
	* HTTP (unencrypted protocols in general)
		* Attacker can pull all kinds of information from packets to send not only corrupt data, but malicious data (ex. modifying packet for sending money to friend to send money to attacker)
	* Pretty much all protocols
		* Attacker can modify data to prevent client from properly communicating with server (ex. you can't ever submit your homework on canvas!!!)
		* Server has no way of verifying that data is not corrupted or changed in transmission

Okay... /rant

For TSFU, there are some assumptions needed, but the assumptions are very minimal and most are EXTREMELY conservative/unecessary.

### Assumptions
Extremely conservative/unecessary assumptions will be denoted with a '+++' at the beginning
* No machines are compromised
	* +++ Keep systems extremely minimal and up to date (to avoid system exploits)
	* NOTE: If your machine is compromised, they have access to your data anyway, so don't blame me
* At least one (hopefully many) WIDELY trusted 3rd parties (kind of like CA's)
	* Assumed to not be malicious
	* Obviously assumed to not be compromised ever (and if they are, they get removed from trusted authorities quickly)
	* Have a public key (+++ 4096+ bits) widely known and trusted (could have the community verify)
* Users of the protocol maintain an updated list (theoretically should RARELY change) of (IP, pubkey) of verified 3rd parties
	* +++ Users of the protocol verify this list when obtaining it
	* TODO: Think of a way to securely update this list
* +++ Good enough random numbers can be generated to be considered "cryptographically secure"

With all that out of the way, it's protocol time!

With each step of the protocol that may have questionable security, I'll provide a short note to clear it up

If I mess something up, let me know!!!!

Submit issues with questions pls I want make this good

NOTE: Ports when sending data are assumed for now.

### TSFU Protocol Walkthrough
##### PACKET DATA STRUCTURE
{(4096 bit secret)(8 bit state of protocol)[arbitrary length (based on current state)]}
1. Handshake (creating a secure channel for client/server to communicate)
	1. Client invokes a TSFU request
		1. A trusted 3rd party (CURRENT_PARTY) from the list is chosen randomly (doesn't matter how random it just should be to semi load balance)
		2. Client generates a (4096+ bit) cryptographically secure random number as a secret (sec)
        3. Client generates a (4096+ bit) random (doesn't need to be cryptographically secure since public) prime (p) and primitive root modulo (g) for a diffie hellman exchange
        4. Client generates a (4096+ bit) cryptographically secure random private key (a) for diffie hellman
        5. Client generates public key A ((g^a) mod p) for diffie hellman
		6. Client sends packet "hello" {(sec)(00000000)(p:4096)(g:4096)(A:4096)} (encrypted with the 3rd party's public key) to the IP of the 3rd party
	2. 3rd party receives encrypted packet from client
		1. Party decrypts packet data, reads state 00000000, and saves A as (Aclient), sec as (clientSec), g, p
		2. Party generates (4096+ bit) cryptographically secure random private keys (bclient) and (bserver) for diffie hellman and secret (newsec)
		3. Party generates public key Bclient ((g^bclient) mod p) for diffie hellman
        4. Party generates public key Bserver ((g^bserver) mod p) for diffie hellman
        5. Party generates common secret sclient ((Aclient^b) mod p)
		6. Party sends packet {(clientSec)(00000001)(Bclient:4096)(newsec:4096)} (encrypted with private key) to the client
            * Visit step 3 and return here
            6.5 Decrypt, verify received newsec, then save servip and finalsec as (finalclientsec)
        7. Party sends packet {(0:4096)(00000010)(g:4096)(p:4096)(Bserver:4096)} (encrypted with private key) to the server ip
            * Visit step 4 and go from there
	* Current questionable points of failure
        * Attacker can't read the request from the client :^)
        * Attacker attempts to modify/forge a malicious request from the client
            * Response from 3rd party will have the wrong clientSec
		* Attacker reads (can't modify) response from 3rd party
			* All the diffie hellman information is public and the attacker can't do nothin bout it
			* The client secret will be revoked/trashed after they verify that the party received the same secret they sent before
    3. Client receives encrypted packet from 3rd party
        1. Client decrypts packet with 3rd party public key, reads state 00000001, verifies first 4096 bits match the secret (terminates handshake unsuccessfully if secret invalid), trashes the secret, then saves Bclient as (B) and newsec
        2. Client calculates a shared secret between them and 3rd party ((A^b) mod p) as (s)
        3. Server generates (4096+ bit) cryptographically secure random secret (finalsec)
        4. Client gets IP of server as (servip)
        5. Client sends packet {(newsec)(00000010)(servip:4096)(finalsec:4096)} (encrypted with 3rd party's public key) to the IP of the 3rd party
    * Current questionable points of failure
        * Attacker intercepts packet from 3rd party to server
            * If they modify it before it gets to the server, it'll be corrupted (they don't have 3rd party's private key), so the transfer just gets cancelled
            * If they try to modify the response from the server, the server will terminate the session, as it will be storing previous state and using diffie hellman with the 3rd party
                * The server needs to store state, since if it didn't, an attacker could replay the initial ping from the 3rd party and modify what the server sends back
    4. Server receives encrypted packet from 3rd party
        1. Server decrypts, checks state is 00000011 and save as (state), Bserver as (B), g, p
        2. Server generates (4096+ bit) cryptographically secure random private key (a) and secret (sec)
        3. Server generates common secret s ((B^a) mod p)
        4. Server generates public key A ((g^a) mod p)
        5. Server generates an rsa public private key pair (pub) (priv)
        6. Server sends packet {(sec)(00000100)(A:4096)(pub:4096)} (encrypted with 3rd party's public key) to the IP of the 3rd party
    5. 3rd party receives encrypted packet from server
        1. Party decrypts, reads state 00000100, saves sec as (serverSec), A as (Aserver), pub
        2. Party generates shared secret sserver ((Aserver^bserver) mod p)
        3. Party AES encrypts the clients ip with sserver as (clientip)
        4. Party AES encrypts pub with sclient as (pubenc)
        5. Server generates (4096+ bit) cryptographically secure random secret (finalserversec)
        6. Party sends packet {(serverSec)(00000101)(clientip:4096)(finalserversec:4096)} (encrypted with servers public key then 3rd party's public key) to the IP of the server
            * Server checks is last state set to 00000011, decrypts with its pub, then 3rd party pub, verifies serverSec correct, checks current state 00000101, decrypts AES clientip with s saved as clientip, then sends packet back {(finalserversec)(00000110)} (encrypted with party's public key)
            * Party decrypts, reads state 00000110, checks finalserversec valid, then is done talking to server!
        7. Party sends packet {(finalclientsec)(00000111)(pubenc:4096)} (encrypted with private key) to the client IP
            * Client decrypts with party's public key, checks finalclientsec valid, decrypts AES pubenc with s as (pub), then everything is done!
    6. Sockets to 3rd party are now closed, as client now has the server's public key,and the server can identify the client

### HANDS HAVE BEEN SHAKEN NOW DATA TRANSFER

This part doesn't really need to be explained as in depth as the handshake

As of now, we have a secure way of transferring data between client and server

They'll do a quick diffie hellman exchange to share a secret to encrypt the actual data exchanged (super redundant, but whateverrrrr it's funnnnnnn)

To take things to the next level, it makes sense to verify that what is sent to the server is complete and not corrupted

To do so................... Blockchain!

Not meme crypto blockchain (that would be gross), but the actual blockchain data structure

To create the blockchain, we'll use a simple doubly linked list like this

...<->{hash: bcrypt(this.previous.hash + currentbyte), data: aes(currentbyte, diffiehellmansecret)}<->{hash: bcrypt(this.previous.hash + nextbyte), data: aes(nextbyte, diffiehellmansecret)}<->... (In this case, the addition sign appends to the byte array)

NOTE: This is disgustingly suboptimal. Will revise after proof of concept. Bit sizes are also up in the air until implementation

In the case the request gets corrupted in transit (someone sets a bunch of bits or who knows), we'll have to have some sort of identifier on the head node to delegate whether it's actually corrupt to begin with

With that in mind, the head node will always be

null<-{hash: bcrypt("2SECURE4UPROTOCOL".bytes + firstbyte), data: aes(firstbyte, diffiehellmansecret)}<->...

The blockchain will take literally FOREVER to compute with these algorithms, so we'll send in chunks

To save memory client side, once the next node in the chain is fully calculated, we take the previous, serialize it into a byte array, encrypt with the servers rsa public key, then send it up

rsa([(hash:184bit)(data:2048bit)])

Depending on implementation, the server can decrypt the data, verify nodes on the fly, then do whatever it wants with the data

### Goals (Ordered by priority)
1. Implement proof of concept locally with some gross python scripts
2. Go through and simulate lots of man in the middle attacks of many different cases and test that protocol acts correctly
2. Add UUID's to proof of concept and have servers able to process multiple requests at a time
3. Implement "3rd party" server, dockerize it, deploy a bunch around different places, and maybe add some kubernetes stuff to deploy a bunch to a single cluster
4. Make client libraries to spawn configurable clients/servers with ease
5. Add tests to client libraries that simulate all kinds of exploits/cases
6. Research into requests/http(s) server libraries and hack together a "tsfu://" protocol that mirrors http(s) functionality with tsfu security
7. Look into actual algorithm optimizations and other ways to make the protocol more stupidly secure/redundant

### Notes

This is all realllllyyyy bad right now

I tried my best for the past 12ish hours to make you all a cool new thing

I don't think I'll give up on this project, so I will definitely definitely definitely revise this later to not be so gross

Suggestions, comments, concerns, contributions, and h8 all welcome!