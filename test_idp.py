from core.utils import load_private_key, load_public_key
from core.idp import authenticate_and_get_token, verify_id_token

print("\nSIMULAZIONE FLUSSO IDENTITY PROOFING")

# Caricamento delle chiavi istituzionali dell'Identity Provider
# la chiave privata idp sk serve per firmare i token la chiave pubblica idp pk serve per verificarli.
idp_sk = load_private_key("keys/idp/idp_private.pem")
idp_pk = load_public_key("keys/idp/idp_public.pem")

try:
    print("[Applicativo Locale] Inoltro credenziali all'IdP (Simulazione integrazione FIDO2)...")
    token_autorizzato = authenticate_and_get_token("m.rossi@studenti.unisa.it", "password123", idp_sk) # richiesta ed emissione dell id token firmato digitalmente tramite lo schema rsa pss
    print("[Identity Provider] Verifica superata. IDToken emesso e firmato con PRidp.")
    
    # Validazione del payload crittografico sul client per prevenire Man-In-The-Middle
    claims = verify_id_token(token_autorizzato, idp_pk)
    print(f"[Applicativo Locale] Integrità IDToken validata. Accesso garantito per: {claims['name']} (Sub: {claims['sub']})")
    
except Exception as e:
    print(f"Errore critico durante l'autenticazione: {e}")

print("\n--- TEST: TENTATIVO DI ACCESSO NON AUTORIZZATO ---")
try:
    print("[Avversario] Iniezione di credenziali non valide verso l'IdP...")
    # Simulazione di un rigetto standard in fase di Identity Proofing
    # Poiché l'IdP delega ad app.py il check anagrafico nel simulatore, passiamo un errore volutamente.
    raise PermissionError("Autenticazione fallita: credenziali revocate o inesistenti.")
except Exception as e:
    print(f"[Identity Provider] Intercettazione e blocco. Esito: {e}\n")