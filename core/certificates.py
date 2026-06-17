import json
import base64
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from core.utils import rsa_sign, rsa_verify, sha256_hex

# Modulo di gestione della PKI
# Simula la Certification Authority per l'emissione dei certificati X.509,
# applicando il mascheramento anagrafico per tutelare l'anonimato dell'elettore.

def load_ca_salt(path: str = "keys/ca/salt.bin") -> bytes:
    # Carica il salt necessario per impedire Dictionary attacks sull'hash della matricola
    with open(path, "rb") as f:
        return f.read()

def compute_pseudonym(matricola: str, salt: bytes) -> str:
    # Calcolo dello pseudonimo univoco: H(matricola || salt).
    # Disaccoppia l'identità reale dalla scheda elettorale.
    return sha256_hex(matricola.encode() + salt)

def _build_tbs(subject: str, issuer: str, not_before: str, not_after: str, public_key) -> bytes:
    # Strutturazione della sezione "To be Signed"del certificato X.509
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    tbs = {
        "subject": subject,
        "issuer": issuer,
        "not_before": not_before,
        "not_after": not_after,
        "public_key": pub_pem.decode(),
    }
    return json.dumps(tbs, sort_keys=True).encode()

def issue_certificate(subject: str, issuer: str, validity_days: int,
                       elettore_public_key, ca_private_key) -> dict:
    # Emissione del certificato digitale
    # La CA vincola matematicamente la chiave pubblica dell'elettore al suo pseudonimo, apponendo la propria firma digitale RSA-PSS
    not_before = datetime.utcnow().isoformat()
    not_after = (datetime.utcnow() + timedelta(days=validity_days)).isoformat()
    tbs = _build_tbs(subject, issuer, not_before, not_after, elettore_public_key)
    signature = rsa_sign(ca_private_key, tbs)
    return {"tbs": tbs, "signature": signature}

def verify_certificate(cert: dict, ca_public_key) -> bool:
    # Validazione crittografica del certificato X.509
    # Simula la risposta protocollare OCSP interrogando la chiave pubblica della CA
    return rsa_verify(ca_public_key, cert["tbs"], cert["signature"])

def get_certificate_subject(cert: dict) -> str:
    # Estrae lo pseudonimo Subject dal certificato
    return json.loads(cert["tbs"])["subject"]

def get_certificate_public_key(cert: dict):
    # Estrae la chiave pubblica dell'elettore per le successive verifiche di firma
    tbs = json.loads(cert["tbs"])
    return serialization.load_pem_public_key(tbs["public_key"].encode())

def save_certificate(cert: dict, path: str):
    # questa funzione si occupa della persistenza del certificato su disco.
    # prende i dati binari del tbs e della firma e li converte in stringhe testuali usando la codifica base64.
    #perchè json non accetta dati grezzi
    serializable = {
        "tbs": base64.b64encode(cert["tbs"]).decode(),
        "signature": base64.b64encode(cert["signature"]).decode(),
    }
    with open(path, "w") as f:
        json.dump(serializable, f)

def load_certificate(path: str) -> dict:
    # questa funzione esegue l operazione inversa per ripristinare il certificato.
    # legge il file json dal disco ed effettua la decodifica da base64 per ricostruire i vettori di byte originali del tbs e della firma digitale.
    # restituisce la struttura dati originale pronta per essere validata dal
    # server tramite la chiave pubblica della certification authority.
    with open(path, "r") as f:
        serializable = json.load(f)
    return {
        "tbs": base64.b64decode(serializable["tbs"]),
        "signature": base64.b64decode(serializable["signature"]),
    }