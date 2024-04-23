import socket
import base64
import nacl.public

class Decoder():
    def __init__(self):
        self.server_url = 'http://cyberlab.pacific.edu:12001'
        self.decoded=[]
        self.socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.response=None
        self.cipher_text=None
        self.public_key_response=None
        self.private_key=None
        # self.public_key=self.convert_asic_to_bin(self.keypair.public_key)

    def socket_connect(self, payload):
        try:
            self.socket.connect(("cyberlab.pacific.edu", 12001))
        except socket.error as error_message:
            print("Error connecting to socket")
        raw_bytes=bytes(payload, 'ascii')
        try:
            self.socket.send(raw_bytes)
        except socket.error as error_message:
            print("Error sending message to socket")
            print("Description: " + error_message)

        response=self.socket.recv(1024)#this connects
        self.socket.close()
        self.response=response.decode('ascii')
        self.assign_public_and_ciphertext()

    def generate_public_private_key(self):
        self.private_key=nacl.public.PrivateKey.generate()
        self.public_key=self.private_key.public_key
        # Convert the public key bytes to a hexadecimal string
        hex_public_key = self.public_key.encode().hex()

        # Convert the hexadecimal public key to ASCII characters
        ascii_public_key = bytes.fromhex(hex_public_key).decode('ascii')

        # Decode the ASCII public key using base64.b16decode
        decoded_public_key = base64.b16decode(ascii_public_key)

        print("final", decoded_public_key)
        return decoded_public_key

    def decode_message(self, private_key):
        print(private_key)
        # Convert ASCII private key to bytes
        binary_private_key = base64.b16decode(private_key)

        # Convert ASCII public key to bytes
        binary_public_key = base64.b16decode(self.public_key_response)

        # Create a private key object from the binary private key
        private_key = nacl.public.PrivateKey(binary_private_key)
        print("binary_private_key:", private_key, "\nbinary_public_key:", binary_public_key)

        # Create a public key object from the binary public key
        public_key = nacl.public.PublicKey(binary_public_key)
        
        # Decode the base64-encoded encrypted message
        decoded_message = base64.b16decode(self.cipher_text)

        # Use the private key to decrypt the message
        decrypted_message = nacl.public.Box(private_key, public_key).decrypt(decoded_message)
        print(decrypted_message)





    def assign_public_and_ciphertext(self):
        index_of_public_key=self.find_start_index(self.response, "PublicKey")+11
        index_of_end_of_public_key=self.find_start_index(self.response[index_of_public_key:], "\r\n")
        self.public_key_response=self.response[index_of_public_key:index_of_public_key+index_of_end_of_public_key]
        
        index_of_cipher_text=self.find_start_index(self.response, "Ciphertext")+12
        index_of_end_of_cipher_text=self.find_start_index(self.response[index_of_cipher_text:], "\r\n")
        self.cipher_text=self.response[index_of_cipher_text:index_of_cipher_text+index_of_end_of_cipher_text]


    def convert_asic_to_bin(self, ascii_string):
        return base64.b16encode(ascii_string)
    def convert_bin_to_ascii_string(self, bin_response):
        return base64.b16decode(bin_response)
    
    def print_response(self):
        print(self.public_key_response)
        print(self.cipher_text)

    def find_start_index(self, original_string, start_word):
        try:
            start_index = original_string.index(start_word)
            return start_index
        except ValueError:
            return -1  # Start word not found

        
def return_payload(name, base64_string_of_key):

    payload=f"""CRYPTO 1.0 REQUEST\r\n
Name: {name}\r\n
PublicKey: {base64_string_of_key}\r\n
\r\n"""
    return payload

def main():
    this=Decoder()
    name="Sevastian Schlau"
    # key=this.generate_public_private_key()
    key="A52F3EADF37ED99F29A5F17F7C1491DE0A1C1DCFA840ABBF2BB9D5489A0D1D4D"
    payload=return_payload(name, key)
    this.socket_connect(payload)
    this.print_response()
    this.decode_message(key)






if __name__=="__main__":
    main()





