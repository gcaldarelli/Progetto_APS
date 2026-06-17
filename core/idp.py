import json
import base64
import time
from core.utils import rsa_sign, rsa_verify, sha256_hex

# Modulo di simulazione dell'Identity Provider di Ateneo.
# Implementa la fase di Identity Proofing rilasciando un IDToken (standard OIDC)
# a seguito della validazione delle credenziali e dello sblocco locale (FIDO2).

def derive_matricola(email: str) -> str:
    #Deriva in modo deterministico una matricola numerica a 10 cifre dall'indirizzo email. (la stessa mail genererà sempre la stessa matricola)
    #una matricola numerica a 10 cifre dall'indirizzo email.
    digest = sha256_hex(email.encode())
    return str(int(digest, 16) % (10 ** 10)).zfill(10)

def authenticate_and_get_token(email: str, password: str, idp_private_key) -> dict:
    # estrazione del nome utente dall indirizzo email e generazione della  matricola
    nome_utente = email.split('@')[0].replace('.', ' ').title()
    matricola_dinamica = derive_matricola(email)

    #strutturazione del payload dell'IDToken con le informazioni essenziali per l'autenticazione e l'autorizzazione.
    claims = {
        "iss": "IdP Universita degli Studi di Salerno",
        "sub": matricola_dinamica,
        "name": nome_utente,
        "email": email,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600
    }

    # serializzazione deterministica dei claims ordinando le chiavi in ordine alfabetico.
    # questo passaggio e fondamentale per garantire che l'hash calcolato per la firma
    # sia identico sia lato emissione che lato verifica prevenendo fallimenti di validazione
    claims_json = json.dumps(claims, sort_keys=True).encode()

    # apposizione della firma digitale dell identity provider idp sul payload json.
    signature = rsa_sign(idp_private_key, claims_json)

    # confezionamento finale dell id token codificando in base64 sia i claims che la firma.
    # questo trasforma i dati binari grezzi in stringhe di testo idonee per essere trasmesse su canali di rete e facilmente manipolabili in ambienti web.
    id_token = {
        "claims": base64.b64encode(claims_json).decode(),
        "signature": base64.b64encode(signature).decode()
    }

    return id_token

def verify_id_token(id_token: dict, idp_public_key) -> dict:
    # Validazione crittografica dell'IDToken tramite la chiave pubblica dell'IdP.
    claims_json = base64.b64decode(id_token["claims"])
    signature = base64.b64decode(id_token["signature"])

    if not rsa_verify(idp_public_key, claims_json, signature):
        raise PermissionError("Firma dell'IDToken non valida: rilevata manomissione.")

    claims = json.loads(claims_json)

    if claims["exp"] < int(time.time()):
        raise PermissionError("IDToken scaduto: necessaria nuova autenticazione.")

    return claims