import os
from core.utils import generate_keypair, save_private_key, save_public_key

KEYS_DIR = "keys"

def setup():
    # Inizializzazione delle directory per la Public Key Infrastructure (PKI)
    es_dir = os.path.join(KEYS_DIR, "election_server")
    ca_dir = os.path.join(KEYS_DIR, "ca")
    idp_dir = os.path.join(KEYS_DIR, "idp") 
    
    os.makedirs(es_dir, exist_ok=True)
    os.makedirs(ca_dir, exist_ok=True)
    os.makedirs(idp_dir, exist_ok=True) 

    # Election Server: Coppia di chiavi per la cifratura
    # Impiegata nel paradigma RSA-OAEP per tutelare la segretezza della scheda
    es_enc_sk, es_enc_pk = generate_keypair()
    save_private_key(es_enc_sk, os.path.join(es_dir, "es_encryption_private.pem"))
    save_public_key(es_enc_pk, os.path.join(es_dir, "es_encryption_public.pem"))

    # Election Server: Coppia di chiavi per la firma digitale (PUfirma, PRfirma)
    # Utilizzata per siglare le ricevute di ritorno tramite RSA-PSS.
    es_sig_sk, es_sig_pk = generate_keypair()
    save_private_key(es_sig_sk, os.path.join(es_dir, "es_signing_private.pem"))
    save_public_key(es_sig_pk, os.path.join(es_dir, "es_signing_public.pem"))

    # Certification Authority (CA): Coppia di chiavi radice (PRca, PUca)
    # Necessaria per validare l'identità pseudonima degli elettori nei certificati X.509
    ca_sk, ca_pk = generate_keypair()
    save_private_key(ca_sk, os.path.join(ca_dir, "ca_root_private.pem"))
    save_public_key(ca_pk, os.path.join(ca_dir, "ca_root_public.pem"))

    # Identity Provider (IdP): Coppia di chiavi per l'emissione dei token (PRidp, PUidp)
    idp_sk, idp_pk = generate_keypair()
    save_private_key(idp_sk, os.path.join(idp_dir, "idp_private.pem"))
    save_public_key(idp_pk, os.path.join(idp_dir, "idp_public.pem"))

    # Generazione del salt 
    # Custodito dalla CA, serve per derivare in modo irreversibile lo pseudonimo dell'elettore.
    salt = os.urandom(32)
    with open(os.path.join(ca_dir, "salt.bin"), "wb") as f:
        f.write(salt)

    print("Setup dell'infrastruttura crittografica completato.")
    print(f" - Chiavi Election Server allocate in: {es_dir}")
    print(f" - Chiavi Certification Authority allocate in: {ca_dir}")
    print(f" - Chiavi Identity Provider allocate in: {idp_dir}")

if __name__ == "__main__":
    setup()