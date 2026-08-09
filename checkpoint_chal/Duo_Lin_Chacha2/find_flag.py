import sys
import os 

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from chal import LinearChaCha20, DoubleLinearCipher

IV1_HEX = "686b0a2d909abbb27736541d"
IV2_HEX = "f8a377f6a7685c6c6020f095"
CIPHERTEXT_FULL_HEX = "144080a5010800200f18400011260102444001a45018624a81092310948cc2084a4000b001860c590900000680491449800a1c40841701b9220000914810c4123a42a0f7430205101c00401020860a0604c011210004222a029002108dc480401200803121ce50172043208d19492008a4021949809108cb3e8860d60b1184109c09f37402706c026379724d074a6b372636147a617f3e3e7f2a713068f3c5"


key1 = bytes.fromhex(input("Enter key1 (hex): "))
key2 = bytes.fromhex(input("Enter key2 (hex): "))
iv1 = bytes.fromhex(IV1_HEX)
iv2 = bytes.fromhex(IV2_HEX)
cpt = bytes.fromhex(CIPHERTEXT_FULL_HEX)

cipher = DoubleLinearCipher(key1, key2, iv1, iv2)
plaintext = cipher.decrypt(cpt)
flag = plaintext[128:]  
print(f"Decrypted flag: {flag.decode()}")

