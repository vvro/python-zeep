import base64
import hashlib
import os
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad


from zeep import ns
from zeep.wss import utils

block_size=16


class UsernameToken:
    """UsernameToken Profile 1.1

        <wss:Security xmlns:wss="http://schemas.xmlsoap.org/ws/2002/12/secext" xmlns:at="http://at.pt/wsp/auth" xmlns:S="http://schemas.xmlsoap.org/soap/envelope/" S:Actor="http://at.pt/actor/SPA" at:Version="2">
            <wss:UsernameToken>
                <wss:Username>599999993/0037</wss:Username>
                <wss:Password Digest="/vj+bxzilIaKWf9d+/6vnlf2jSttTyUsmTxK66YbGCQ=&#10;">0h5MQdAbc2xYBpXJd/P+qQ==
                </wss:Password>
                <wss:Nonce>J3+HbXMIOhfFPJHwf6hlEz7gVkk22Is7jlHwkbpB17jqbG4BUNWZd/9tZGDxLzN0OvyvzmNaSWVT
rQIYJ4Ev5GIUECe7xGOvZN92lk/mIGtp3/6iauOOGeOxZw4IVZWnvVzx5FC7p/i1BrDGNkolWvwK
tAh6HE31968/9TKcDCu2TVKLNYxTpLM9elSNNl2ZT0zgS3OK5JoJt+Hb/M//lRAUhpeT/tNNcX9p
9i598EN2CyDBfU0u5psy5NaH4sYebV1TR8pYPWNDzkat7Rsu35CfWTq8gewIDhqoyeJhRhO89EGV
7c/Qpe5NcHz5/OVA+eQ2UdFi0x9lCDjpRbqNyg==
                </wss:Nonce>
                <wss:Created>2022-10-31T16:54:33.437Z</wss:Created>
            </wss:UsernameToken>
        </wss:Security>

    
    """

    username_token_profile_ns = "https://schemas.xmlsoap.org/ws/2002/12/secext/secext.xsd"  # noqa
    soap_message_secutity_ns = "https://schemas.xmlsoap.org/ws/2002/12/secext/secext.xsd"  # noqa

    def __init__(
        self,
        username,
        password=None,
        password_digest=None,
        use_digest=False,
        nonce=None,
        created=None,
        timestamp_token=None,
        zulu_timestamp=None,
        hash_password=None,
        rsa=None,
    ):
        """
        Some SOAP services want zulu timestamps with Z in timestamps and
        in password digests they may want password to be hashed before
        adding it to nonce and created.
        """
        self.username = username
        self.password = password
        self.password_digest = password_digest
        self.nonce = nonce
        self.created = created
        self.use_digest = use_digest
        self.timestamp_token = timestamp_token
        self.zulu_timestamp = zulu_timestamp
        self.hash_password = hash_password
        self.rsa = rsa

    def apply(self, envelope, headers):
        security = utils.get_security_header(envelope)

        # The token placeholder might already exists since it is specified in
        # the WSDL.
        token = security.find("{%s}UsernameToken" % ns.WSS)
        if token is None:
            token = utils.WSS.UsernameToken()
            security.append(token)

        if self.timestamp_token is not None:
            security.append(self.timestamp_token)

        # Create the sub elements of the UsernameToken element
        elements = [utils.WSS.Username(self.username)]
        if self.password is not None or self.password_digest is not None:
            if self.use_digest:
                elements.extend(self._create_password_digest())
            else:
                elements.extend(self._create_password_text())

        token.extend(elements)
        return envelope, headers
    
    

    def encrypt(self,plainText,key):
        block_size=16
        
        aes = AES.new(key, AES.MODE_ECB)    
        encrypt_aes = aes.encrypt(pad(plainText,block_size))
        #encrypted_text = base64.b64encode(encrypt_aes).decode('utf-8')
        return encrypt_aes


    def verify(self, envelope):
        pass

    def _create_password_text(self):
        return [
            utils.WSS.Password(
                self.password
            )
        ]

    def _create_password_digest(self):
        if self.nonce:
            nonce = self.nonce.encode("utf-8")
        else:
            nonce = os.urandom(16)
        timestamp = utils.get_timestamp(self.created, self.zulu_timestamp)

        if isinstance(self.password, str):
            password = self.password.encode("utf-8")
        else:
            password = self.password

        # digest = Base64 ( SHA-1 ( nonce + created + password ) )
        pass_digest = base64.b64encode(
                hashlib.sha1(
                    nonce + timestamp.encode("utf-8") + password
                ).digest()
            )
        if not self.password_digest and self.hash_password:
            digest = self.encrypt(password,nonce)
        elif not self.password_digest:
            digest = self.encrypt(password,nonce)
        else:
            digest = self.encrypt(password,nonce)
            
        if self.rsa:
            key = RSA.importKey(open(self.rsa,'r').read())
            cipher = PKCS1_v1_5.new(key)
            
            etimestamp = self.encrypt(timestamp.encode('utf-8'),nonce)
            edigest = self.encrypt(pass_digest,nonce)
            nonce = cipher.encrypt(nonce)          
            return [
            utils.WSS.Password(
                base64.b64encode(digest).decode('utf-8'), 
                Digest = base64.b64encode(edigest).decode('utf-8')
            ),
            utils.WSS.Nonce(
                base64.b64encode(nonce).decode('utf-8')
            ),
            utils.WSS.Created(
                timestamp
                #timestamp
                ),
        ]
