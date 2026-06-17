from core.utils import generate_keypair, load_private_key, load_public_key
from core.certificates import (
    load_ca_salt, compute_pseudonym, issue_certificate,
    verify_certificate, get_certificate_subject, get_certificate_public_key,
)

print("\nSIMULAZIONE EMISSIONE CERTIFICATO DIGITALE X.509")

# Generazione isolata della coppia di chiavi sul dispositivo dell'elettore
elettore_sk, elettore_pk = generate_keypair()

salt = load_ca_salt()
subject = compute_pseudonym("0512345678", salt)
print(f"[CA] Pseudonimo crittografico derivato: {subject}")

# Apposizione della firma radice (PRca) per attestare la validità della chiave pubblica dell'elettore
ca_sk = load_private_key("keys/ca/ca_root_private.pem")
cert = issue_certificate(
    subject=subject,
    issuer="CA Università degli Studi di Salerno",
    validity_days=7,
    elettore_public_key=elettore_pk,
    ca_private_key=ca_sk,
)

# L'Election Server (o un verificatore terzo) accerta la validità del certificato tramite PUca
ca_pk = load_public_key("keys/ca/ca_root_public.pem")
print(f"[Verificatore] Controllo validità firma CA: {verify_certificate(cert, ca_pk)}")
print(f"[Verificatore] Subject estratto dal certificato: {get_certificate_subject(cert)}")

extracted_pk = get_certificate_public_key(cert)
pk_match = extracted_pk.public_numbers() == elettore_pk.public_numbers()
print(f"[Verificatore] Corrispondenza chiave pubblica (Integrità garantita): {pk_match}\n")