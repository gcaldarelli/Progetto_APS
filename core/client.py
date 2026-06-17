import base64
import json
from core.utils import (
    generate_keypair, rsa_encrypt, rsa_sign, rsa_verify, sha256_hex
)
from core.merkle_tree import generate_proof_by_hash, verify_proof

class ElettoreClient:
    def __init__(self, es_encryption_public_key, es_signing_public_key, ca_public_key):
        # parametri crittografici di sistema distribuiti out-of-band all'applicativo client
        self.es_enc_pk = es_encryption_public_key
        self.es_sig_pk = es_signing_public_key
        self.ca_pk = ca_public_key
        
        # la chiave privata sk non deve mai lasciare il dispositivo
        self.sk = None      
        self.pk = None      
        self.cert = None    
        self.receipt = None 

    def generate_local_credentials(self):
        # generazione locale della coppia di chiavi RSA.
        self.sk, self.pk = generate_keypair()
        return self.pk

    def receive_certificate(self, certificate: dict):
        # Memorizza il certificato X.509 contenente lo pseudonimo
        self.cert = certificate

    def cast_vote(self, voto_intero: int) -> str:
        #paradigma Encrypt-then-Authenticate
        if self.cert is None or self.sk is None:
            raise PermissionError("Credenziali mancanti: impossibile procedere alla votazione.")
        
        # 1 preparazione del plaintext (v = intero compreso tra 1 e 5)
        m = str(voto_intero).encode()

        # 2 cifratura asimmetrica con RSA-OAEP
        c_bytes = rsa_encrypt(self.es_enc_pk, m)
        c_b64 = base64.b64encode(c_bytes).decode()

        # 3 firma digitale RSA-PSS applicando hash and sign
        sigma_bytes = rsa_sign(self.sk, c_bytes)
        sigma_b64 = base64.b64encode(sigma_bytes).decode()

        # 4 composizione del pacchetto di voto (serializzazione sicura in JSON)
        cert_for_network = {
            "tbs": base64.b64encode(self.cert["tbs"]).decode(),
            "signature": base64.b64encode(self.cert["signature"]).decode()
        }


        # composizione finale della busta elettorale.
        # inseriamo il testo cifrato c, la firma digitale sigma e il certificato emesso dalla ca per l autenticazione.
        packet = {
            "C": c_b64,
            "sigma": sigma_b64,
            "cert": cert_for_network
        }
        
        return json.dumps(packet)

    def process_receipt(self, receipt: dict, sent_c_b64: str):
        # estrazione dell hash del voto e della firma digitale dell election server dalla ricevuta.
        # decodifichiamo la firma da base64 in byte 
        h_server = receipt["h"]
        sigma_es = base64.b64decode(receipt["sigma_ES"])

        h_locale = sha256_hex(sent_c_b64.encode())

        # controllo di coerenza per verificare che l'election server abbia registrato esattamente lo stesso identico pacchetto trasmesso dal client.
        # serve a rilevare immediatamente anomalie o alterazioni nel transito sui canali di rete.
        if h_server != h_locale:
            raise ValueError("Incongruenza crittografica: l'hash della ricevuta non corrisponde al ciphertext inviato.")

        # verifica rigorosa della firma digitale rsa pss sull hash usando la chiave pubblica.
        if not rsa_verify(self.es_sig_pk, h_server.encode(), sigma_es):
            raise PermissionError("Firma della ricevuta non valida: possibile compromissione o manomissione.")

        # se tutte le verifiche crittografiche hanno successo la ricevuta viene salvata in memoria.
        self.receipt = receipt

    def verify_vote_in_urn(self, public_results: dict):
        # Verificabilità individuale post-elezione.
        # Il client opera interamente in locale per non esporre il proprio indirizzo IP all'Election Server
        # ed estrae la Proof of Membership per verificare che h sia foglia del Merkle Tree
        if not self.receipt:
            return False

        my_hash = self.receipt["h"]
        tree = public_results["merkle_tree"]
        root = public_results["merkle_root"]

        try:
            proof = generate_proof_by_hash(my_hash, tree)
            if verify_proof(my_hash, proof, root):
                return True
            else:
                return False
        except ValueError:
            return False