import base64
import json
from core.utils import (
    rsa_verify, rsa_sign, rsa_decrypt, sha256_hex
)
from core.certificates import (
    verify_certificate, get_certificate_subject, get_certificate_public_key
)
from core.merkle_tree import build_shuffled_merkle_tree

class ElectionServer:
    def __init__(self, ca_public_key, es_signing_private_key, es_encryption_private_key):
        self.ca_pk = ca_public_key
        self.es_sig_sk = es_signing_private_key
        self.es_enc_sk = es_encryption_private_key
        
        # registro transazionale degli accessi (memorizza solo gli pseudonimi che hanno già votato)
        self.voters_db = set()
        
        # urna digitale: registro append-only contenente esclusivamente i ciphertext anonimi
        self.tamper_evident_log = []
        
        self.is_open = True
        self.last_results = None

    def receive_vote(self, packet_json: str) -> dict:
        #processa il pacchetto di voto in ingresso eseguendo le validazioni crittografiche
        if not self.is_open:
            raise PermissionError("Operazione negata: le urne sono chiuse.")

        packet = json.loads(packet_json)
        c_b64 = packet["C"]
        sigma_b64 = packet["sigma"]
        cert_network = packet["cert"]

        c_bytes = base64.b64decode(c_b64)
        sigma_bytes = base64.b64decode(sigma_b64)
        cert = {
            "tbs": base64.b64decode(cert_network["tbs"]),
            "signature": base64.b64decode(cert_network["signature"])
        }

        # Simulazione protocollo OCSP:
        # L'Election Server interroga la CA in tempo reale per assicurarsi che il
        # certificato non sia stato revocato o compromesso prima di accettare il pacchetto.
        if not verify_certificate(cert, self.ca_pk):
            raise ValueError("Certificato non valido o revocato (Controllo OCSP fallito).")
        
        # Controllo unicità per prevenire il voto multiplo
        subject = get_certificate_subject(cert)
        if subject in self.voters_db:
            raise PermissionError("Voto già registrato per questo pseudonimo.")

        # Verifica della firma 
        # Garantisce che il pacchetto non sia stato alterato da un avversario esterno
        elettore_pk = get_certificate_public_key(cert)
        if not rsa_verify(elettore_pk, c_bytes, sigma_bytes):
            raise ValueError("Integrità compromessa: la firma digitale RSA-PSS non è valida.")

        # Controllo duplicati del Ciphertext
        if c_b64 in self.tamper_evident_log:
            raise ValueError("Rilevata anomalia crittografica: Ciphertext duplicato (Replay Attack).")

        # Scissione Irreversibile per la garanzia dello pseudoanonimato
        # L'Election Server separa definitivamente lo pseudonimo dalla scheda cifrata C.
        # Lo pseudonimo viene inserito nel registro accessi, mentre C finisce nell'urna anonima.
        # La firma locale e il certificato vengono volutamente non salvati per, 
        # spezzare ogni legame logico e impedire la ricostruzione dell'associazione mittente-voto.
        self.voters_db.add(subject)
        self.tamper_evident_log.append(c_b64)

        # Emissione della ricevuta crittografica
        # Il server firma l'hash del ciphertext, garantendo all'elettore il non-ripudio dell'avvenuta ricezione
        h = sha256_hex(c_b64.encode())
        sigma_es = rsa_sign(self.es_sig_sk, h.encode())

        return {"h": h, "sigma_ES": base64.b64encode(sigma_es).decode()}

    def close_polls_and_tally(self) -> dict:
         #congela il registro, avvia lo spoglio e genera le strutture per la verificabilità
        if self.last_results is not None:
            return self.last_results

        self.is_open = False
        tally = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
        
        # Apertura dell'urna e decifratura dei voti
        # L'Election Server utilizza la propria chiave privata per estrarre i plaintext
        for c_b64 in self.tamper_evident_log:
            c_bytes = base64.b64decode(c_b64)
            m_bytes = rsa_decrypt(self.es_enc_sk, c_bytes)
            voto = int(m_bytes.decode())
            if voto in tally:
                tally[voto] += 1

        # Costruzione dell'Albero di Merkle
        # Viene creata la struttura dati pubblica che culmina nella Merkle Root. Questo permette:
        # Verificabilità Universale: la rete può accertare che l'urna non sia stata alterata.
        # Verificabilità Individuale: i client possono estrarre la Proof of Membership.
        root, tree, shuffled_list = build_shuffled_merkle_tree(self.tamper_evident_log)
        self.tamper_evident_log = shuffled_list
        
        self.last_results = {
            "results": tally,
            "merkle_root": root,
            "merkle_tree": tree,
            "pseudonimi_pubblicati": list(self.voters_db) 
        }
        return self.last_results