from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
import hashlib

# Modulo di utilità crittografica.
# Astrae le primitive di base della libreria 'cryptography' per fornire 
# interfacce standardizzate a tutte le componenti del sistema di voto.

def sha256_hex(data: bytes) -> str:
    # Calcola il digest SHA-256
    return hashlib.sha256(data).hexdigest()

def generate_keypair():
    # Genera una coppia di chiavi asimmetriche RSA.
    # La dimensione di 2048 bit offre un livello di sicurezza adeguato 
    # per il contesto accademico e i tempi di vita previsti per l'elezione.
    sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return sk, sk.public_key()

def rsa_encrypt(public_key, plaintext: bytes) -> bytes:
    # Cifratura asimmetrica con schema RSA-OEP
    return public_key.encrypt(
        plaintext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    # Decifratura asimmetrica RSA-OAEP. 
    # Utilizzata dall'Election Server in fase di spoglio
    return private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def rsa_sign(private_key, data: bytes) -> bytes:
    # Generazione della firma digitale con schema RSA-PSS 
    return private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

def rsa_verify(public_key, data: bytes, signature: bytes) -> bool:
    # Validazione crittografica della firma RSA-PSS.
    # Restituisce True se l'integrità e l'autenticità del dato sono confermate, False altrimenti.
    try:
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False

# Funzioni di Input/Output per la persistenza delle chiavi 

def save_private_key(private_key, path: str):
    # questa funzione si occupa di esportare e salvare la chiave privata sul disco
    # converte la chiave in un blocco di testo codificato in formato standard pem
    # l algoritmo di cifratura è impostato a nessuna crittografia per motivi di 
    # semplicita didattica evitando l inserimento continuo di password nel simulatore.
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(), # Nessuna password locale (setup didattico)
    )
    with open(path, "wb") as f:
        f.write(pem)

def save_public_key(public_key, path: str):
    # gestisce la persistenza della chiave pubblica scrivendola in un file locale
    # questa chiave sara distribuita ai vari attori per cifrare o verificare firme
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(path, "wb") as f:
        f.write(pem)

def load_private_key(path: str):
    # esegue l operazione inversa leggendo una chiave privata memorizzata su disco
    # ricostruisce in memoria l oggetto chiave privata rsa pronto per apporre firme
    # digitali rsa pss o decifrare i dati
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(path: str):
    # ricarica in memoria una chiave pubblica leggendola dal percorso specificato.
    # decodifica i byte in formato pem per ripristinare le proprieta matematiche
    # della chiave asimmetrica usata dall election server o dall applicativo client
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())