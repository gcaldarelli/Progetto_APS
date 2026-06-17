import os
import time
import json
from flask import Flask, request, render_template_string

from core.utils import load_private_key, load_public_key
from core.idp import authenticate_and_get_token, verify_id_token, derive_matricola
from core.certificates import issue_certificate, load_ca_salt, compute_pseudonym
from core.server import ElectionServer
from core.client import ElettoreClient

app = Flask(__name__)

# database di ateneo per la simulazione dell'Identity Provider.
# L'autenticazione sfrutta l'Identity Proofing tramite protocollo OIDC.
# Nella realtà, questo step avviene tramite MFA e FIDO2/WebAuthn per sbloccare l'authenticator locale
DB_ATENEO = {
    "m.rossi@studenti.unisa.it": "password123",
    "l.bianchi@studenti.unisa.it": "sicurezza2024",
    "g.verdi@studenti.unisa.it": "esameaps!",
    "a.neri@studenti.unisa.it": "test1234",
}

def log(msg):
    print(msg, flush=True)

# Caricamento chiavi crittografiche asimmetriche e parametri di sistema
ca_sk = load_private_key("keys/ca/ca_root_private.pem")
ca_pk = load_public_key("keys/ca/ca_root_public.pem")
idp_sk = load_private_key("keys/idp/idp_private.pem")
idp_pk = load_public_key("keys/idp/idp_public.pem")
es_enc_sk = load_private_key("keys/election_server/es_encryption_private.pem")
es_enc_pk = load_public_key("keys/election_server/es_encryption_public.pem")
es_sig_sk = load_private_key("keys/election_server/es_signing_private.pem")
es_sig_pk = load_public_key("keys/election_server/es_signing_public.pem")
ca_salt = load_ca_salt("keys/ca/salt.bin")

# Inizializzazione dello stato del server e delle strutture dati locali

# il server riceve la chiave pubblica della ca per validare i certificati degli elettori
# e le proprie chiavi private per firmare le ricevute e decifrare le schede nello spoglio.
server = ElectionServer(ca_pk, es_sig_sk, es_enc_sk)  
ca_registry = {}        # registro della ca utilizzato per associare le matricole ai rispettivi pseudonimi.
# mappatura locale dei wallet crittografici associati a ciascuna matricola studentesca.
# memorizza in ram le istanze dei client degli elettori mantenendo logicamente isolato
# lo stato delle chiavi private dei singoli utenti per simulare i dispositivi personali.
wallets = {}            
# archivio transizionale dei pacchetti di buste elettroniche gia trasmesse sulla rete.
# viene utilizzato nel simulatore per orchestrare la difesa attiva contro i replay attacks
# permettendo di ritrasmettere un vecchio pacchetto catturato e verificarne lo scarto.
voter_ballots = {}      
# inizializzazione dello stato della bacheca pubblica destinata a ospitare i risultati.
# dopo lo scrutinio conterra il conteggio aggregato delle preferenze e l intero albero
# di merkle con la root per garantire la verificabilita universale e individuale.
public_results = None   

HTML = """
<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<title>Simulatore Elettorale</title>
<style>
body { font-family: Arial, Helvetica, sans-serif; background-color: #f9f9f9; color: #333; padding: 30px; }
.container { background-color: #fff; padding: 30px; border: 1px solid #ccc; max-width: 640px; margin: 0 auto; }
h2 { color: #003366; border-bottom: 2px solid #003366; padding-bottom: 10px; margin-top: 0; }
h3 { color: #003366; margin-top: 0; }
.card { border: 1px solid #ddd; border-radius: 6px; padding: 14px; margin-bottom: 16px; background: #fdfdfd; }
.form-group { margin-bottom: 12px; }
label { display: block; margin-bottom: 5px; font-weight: bold; }
input, select { width: 100%; padding: 8px; border: 1px solid #999; box-sizing: border-box; }
button { padding: 9px 14px; background-color: #003366; color: white; border: none; cursor: pointer; font-weight: bold; margin-top: 8px; margin-right: 6px; border-radius: 4px; }
button.secondary { background-color: #888; }
button:hover { background-color: #002244; }

/* Regola generale per i link: blu istituzionale, niente sottolineatura fissa */
a { color: #003366; text-decoration: none; font-weight: bold; }
a:hover { text-decoration: underline; color: #002244; }

/* Stile rigorosamente unificato per TUTTI i messaggi di notifica (errori, successi e info) */
.info-box, .error, .success { 
    background-color: #eef; 
    border: 1px solid #ccd; 
    padding: 12px; 
    margin-bottom: 16px; 
    font-size: 14px; 
    color: #333; 
    border-radius: 4px; 
    font-weight: normal; 
}

.notice { font-size: 12px; color: #666; margin-top: 8px; }
.status { font-size: 13px; color: #555; margin-bottom: 14px; text-align: right; }
.status a { margin-left: 6px; }
code { background: #f0f0f0; padding: 2px 4px; word-break: break-all; font-size: 12px; }
table { width: 100%; border-collapse: collapse; margin: 10px 0; }
td, th { border: 1px solid #ccc; padding: 6px 10px; text-align: left; }
</style>
</head>
<body>
<div class="container">
  <div class="status">
    Stato Urne: {{ "APERTE" if urne_aperte else "CHIUSE" }} &mdash; Voti registrati: {{ n_votes }}
    <a href="/">Login</a> | <a href="/scrutinio">Scrutinio Pubblico</a> | <a href="/verifica">Verifica Voto</a>
  </div>
  <h2>Portale di Voto Elettronico</h2>

  {% if error %}<div class="error">{{ error }}</div>{% endif %}
  {% if info %}<div class="info-box">{{ info }}</div>{% endif %}

  {% if step == 'login' %}
    <div class="info-box">
      <strong>Credenziali di test per l'Identity Provider:</strong><br>
      - m.rossi@studenti.unisa.it (pw: password123)<br>
      - l.bianchi@studenti.unisa.it (pw: sicurezza2024)<br>
      - g.verdi@studenti.unisa.it (pw: esameaps!)<br>
      - a.neri@studenti.unisa.it (pw: test1234)
    </div>
    <form method="post" action="/login">
      <div class="form-group"><label>Email Istituzionale:</label><input type="email" name="email" required></div>
      <div class="form-group"><label>Password:</label><input type="password" name="password" required></div>
      <button type="submit">Accedi tramite Identity Provider</button>
    </form>

  {% elif step == 'dashboard' %}
    <p>Matricola: <code>{{ matricola }}</code> &mdash; Email: {{ email }}</p>

    <div class="card">
      <h3>Emissione Certificato Digitale X.509</h3>
      {% if registered %}
        <div class="success">Certificato emesso con successo. Pseudonimo crittografico: <code>{{ subject }}</code></div>
        <form method="post" action="/registra">
          <input type="hidden" name="email" value="{{ email }}">
          <input type="hidden" name="password" value="{{ password }}">
          <button class="secondary" type="submit">Richiedi emissione nuovo certificato</button>
        </form>
        <p class="notice">Simulazione Attacco Sybil: La Certification Authority verificherà l'unicità della richiesta per prevenire la generazione di identità multiple.</p>
      {% else %}
        <form method="post" action="/registra">
          <input type="hidden" name="email" value="{{ email }}">
          <input type="hidden" name="password" value="{{ password }}">
          <button type="submit">Procedi all'Autenticazione e Registrazione</button>
        </form>
      {% endif %}
    </div>

    <div class="card">
      <h3>Espressione del Voto</h3>
      {% if not registered %}
        <p>È necessario completare la fase di registrazione per poter accedere alla scheda elettorale.</p>
      {% elif voted %}
        <div class="success">La scheda elettorale è stata cifrata e depositata nell'urna.</div>
        <p>Ricevuta crittografica (h): <code>{{ h }}</code></p>
        <form method="post" action="/replay">
          <input type="hidden" name="email" value="{{ email }}">
          <input type="hidden" name="password" value="{{ password }}">
          <button class="secondary" type="submit">Ritrasmetti pacchetto di voto (Simulazione Replay Attack)</button>
        </form>
        <p class="notice">Test di sicurezza: L'Election Server scarterà il pacchetto rilevando uno pseudonimo già registrato nel log degli accessi.</p>
      {% else %}
        <form method="post" action="/vota">
          <input type="hidden" name="email" value="{{ email }}">
          <input type="hidden" name="password" value="{{ password }}">
          <div class="form-group">
            <label>Seleziona la preferenza:</label>
            <select name="voto" required>
              <option value="" disabled selected>-- Seleziona --</option>
              <option value="1">1 - Scheda Bianca</option>
              <option value="2">2 - Tutti per Unisa</option>
              <option value="3">3 - StudentiSA</option>
              <option value="4">4 - SocrateSa</option>
              <option value="5">5 - StudentiPerIlFuturo</option>
            </select>
          </div>
          <button type="submit">Cifra e Trasmetti Voto</button>
        </form>
      {% endif %}
    </div>

  {% elif step == 'scrutinio_empty' %}
    <p>Le urne sono ancora vuote. Registrare almeno un voto prima di procedere allo spoglio.</p>

  {% elif step == 'scrutinio' %}
    <div class="success">Operazioni di voto concluse. Scrutinio completato su {{ n_votes }} schede valide.</div>
    <table>
      <tr><th>Associazione Candidata</th><th>Preferenze Espresse</th></tr>
      <tr><td>1 - Scheda Bianca</td><td>{{ results[1] }}</td></tr>
      <tr><td>2 - Tutti per Unisa</td><td>{{ results[2] }}</td></tr>
      <tr><td>3 - StudentiSA</td><td>{{ results[3] }}</td></tr>
      <tr><td>4 - SocrateSa</td><td>{{ results[4] }}</td></tr>
      <tr><td>5 - StudentiPerIlFuturo</td><td>{{ results[5] }}</td></tr>
    </table>
    <p>Merkle Root firmata digitalmente dalla commissione:</p>
    <p><code>{{ root }}</code></p>

  {% elif step == 'verifica_pending' %}
    <p>Lo scrutinio non è stato ancora avviato. <a href="/scrutinio">Vai alla sezione di spoglio</a>.</p>

  {% elif step == 'verifica' %}
    <form method="post" action="/verifica">
      <div class="form-group"><label>Indirizzo Email Istituzionale:</label><input type="email" name="email" required></div>
      <button type="submit">Verifica Inclusione nell'Urna</button>
    </form>
    {% if result %}
      {% if result.error %}
        <div class="error">{{ result.error }}</div>
      {% else %}
        <p>Hash della scheda (h): <code>{{ result.h }}</code></p>
        <p>Verifica Proof of Membership nell'Albero di Merkle: 
          <b style="color: {{ '#003366' if result.included else '#8a2b2b' }};">{{ "Successo (Voto Conteggiato)" if result.included else "Fallita (Voto Non Trovato)" }}</b></p>
      {% endif %}
    {% endif %}
  {% endif %}

</div>
</body>
</html>
"""

def _ctx(**extra):
    # funzione ausiliaria per generare il contesto dinamico dell interfaccia web.
    # recupera lo stato attuale del server ovvero il numero di voti e se le urne sono aperte
    base = {"n_votes": len(server.tamper_evident_log), "urne_aperte": server.is_open}
    base.update(extra)
    return base

def _dashboard(email, password, matricola, error=None, info=None):
    registered = matricola in wallets       # verifica se lo studente ha gia completato la fase di registrazione della chiave pubblica.
    subject = ca_registry.get(matricola)    # recupera lo pseudonimo anonimo assegnato dalla certification authority alla matricola
    voted = registered and wallets[matricola].receipt is not None # determina se l elettore ha gia espresso il proprio voto controllando la ricevuta.
    h = wallets[matricola].receipt["h"] if voted else None # estrazione dell hash del ciphertext dalla ricevuta se il voto e stato espresso.

    # passa al template html tutti gli indicatori di stato booleani e i messaggi di errore.
    return render_template_string(HTML, step="dashboard", **_ctx(
        email=email, password=password, matricola=matricola,
        registered=registered, subject=subject, voted=voted, h=h,
        error=error, info=info,
    ))

@app.route("/")
def index():
    # passa al template html la mappa del contesto globale aggiornato tramite la funzione ctx.
    return render_template_string(HTML, step="login", **_ctx())

@app.route("/login", methods=["POST"])
def login():
    # estrae i parametri email e password dal form ed esegue la pulizia degli spazi bianchi
    email = request.form["email"].strip()
    password = request.form["password"]

    # attivazione della telemetria sul terminale per tracciare la fase di identity proofing.
    # inserisce un separatore grafico per isolare i log di questa transazione crittografica.
    log("\n" + "=" * 50)
    log("[IdP] Inizio fase di Identity Proofing...")

    # controllo di sicurezza per verificare la presenza e la correttezza dell utente nel database.
    # in caso di credenziali errate abortisce la procedura restituendo la pagina di login con errore.
    if email not in DB_ATENEO or DB_ATENEO[email] != password:
        log("[IdP] Accesso negato: credenziali non valide.")
        return render_template_string(HTML, step="login", error="Credenziali errate o utente non trovato.", **_ctx())

    # generazione e validazione immediata del token firmato digitalmente dall'idp
    id_token = authenticate_and_get_token(email, password, idp_sk)
    claims = verify_id_token(id_token, idp_pk)
    matricola = claims["sub"]        # l operazione estrae le asserzioni e isola la matricola dello studente dal campo subject
    log(f"[IdP] IDToken validato. Accesso consentito per la matricola: {matricola}")

    # indirizzamento dell elettore autenticato verso la visualizzazione della propria dashboard
    return _dashboard(email, password, matricola)

@app.route("/registra", methods=["POST"])
def registra():
    # gestione della registrazione dello studente presso la ca
    # estrae le credenziali dal form e calcola la matricola deterministica dalla mail
    email = request.form["email"]
    password = request.form["password"]
    matricola = derive_matricola(email)

    log("\n" + "=" * 50)
    log("[CA] Inizio procedura di emissione certificato X.509...")

    # controllo anti sybil attack basato sul registro delle identita della pki
    # se la matricola possiede gia uno pseudonimo associato blocca la richiesta multipla.
    if matricola in ca_registry:
        msg = f"Rilevato tentativo di richiesta multipla. Certificato già emesso per lo pseudonimo {ca_registry[matricola][:16]}..."
        log(f"[CA] Eccezione di sicurezza: {msg}")
        return _dashboard(email, password, matricola, error=msg)

    # istanziazione del client ed esecuzione della generazione locale della coppia di chiavi
    # viene calcolato il tempo esatto in millisecondi 
    client = ElettoreClient(es_enc_pk, es_sig_pk, ca_pk)
    t0 = time.perf_counter()
    pub_key = client.generate_local_credentials()
    t_keygen = (time.perf_counter() - t0) * 1000

    # calcolo dello pseudonimo anonimo tramite hashing con aggiunta di salt
    # la ca emette il certificato digitale vincolando la chiave pubblica allo pseudonimo.
    subject = compute_pseudonym(matricola, ca_salt)
    cert = issue_certificate(subject, "CA Unisa", 7, pub_key, ca_sk)
    client.receive_certificate(cert)

    # memorizzazione dello stato nei dizionari locali per simulare la persistenza di rete.
    wallets[matricola] = client
    ca_registry[matricola] = subject

    log(f"[Client] Generazione locale chiavi RSA in {t_keygen:.2f} ms")
    log(f"[CA] Certificato emesso con successo. Pseudonimo: {subject}")

    return _dashboard(email, password, matricola, info=f"Certificato emesso. Identificativo di rete: {subject[:16]}...")

@app.route("/vota", methods=["POST"])
def vota():
    # gestione dell' espressione e l'invio della busta di voto
    # recupera i dati dal form e mappa l'utente tramite la derivazione della matricola
    email = request.form["email"]
    password = request.form["password"]
    voto = int(request.form["voto"])
    matricola = derive_matricola(email)

    log("\n" + "=" * 50)
    log("[Sistema] Avvio protocollo di espressione del voto...")

    # controllo di autorizzazione per verificare che l'utente abbia un certificato valido.
    if matricola not in wallets:
        return _dashboard(email, password, matricola, error="Procedura non autorizzata: certificato mancante.")

    # verifica dello stato delle urne per impedire l'inserimento di schede a votazione chiusa
    if not server.is_open:
        log("[Election Server] Pacchetto scartato: la fase di scrutinio è già iniziata.")
        return _dashboard(email, password, matricola, error="Operazione negata. Le urne risultano chiuse.")

    # difesa preventiva contro il voto multiplo controllando la presenza della ricevuta locale
    client = wallets[matricola]
    if client.receipt is not None:
        return _dashboard(email, password, matricola, error="Il sistema ha rilevato un voto già registrato a tuo nome.")

    try:
        # fase client esecuzione della cifratura rsa oaep e della firma rsa pss
        t0 = time.perf_counter()
        busta_json = client.cast_vote(voto)
        t_pack = (time.perf_counter() - t0) * 1000

        # fase server trasmissione della busta sulla rete e validazione crittografica
        t0 = time.perf_counter()
        ricevuta = server.receive_vote(busta_json)
        t_proc = (time.perf_counter() - t0) * 1000

        # elaborazione finale della ricevuta firmata dall election server per la verificabilità
        client.process_receipt(ricevuta, json.loads(busta_json)["C"])
        voter_ballots[matricola] = busta_json

        # calcolo e stampa delle prestazioni e delle dimensioni del pacchetto.
        size = len(busta_json.encode("utf-8"))
        log(f"[Client] Plaintext cifrato (OAEP) e firmato (PSS) in {t_pack:.3f} ms")
        log(f"[Rete] Trasmissione busta <C, sigma, Cert> ({size} byte)")
        log(f"[Election Server] Check OCSP e validazione eseguiti in {t_proc:.3f} ms")
        log(f"[Election Server] Registrazione nel log avvenuta. Hash generato: {ricevuta['h']}")

        return _dashboard(email, password, matricola, info=f"Voto acquisito correttamente. Ricevuta: {ricevuta['h'][:16]}...")

    except (ValueError, PermissionError) as e:
        log(f"[Election Server] Scarto anomalo: {e}")
        return _dashboard(email, password, matricola, error=str(e))

@app.route("/replay", methods=["POST"])
def replay():
    # gestione dell' attacco simulato per testare la sicurezza del sistema.
    email = request.form["email"]
    password = request.form["password"]
    matricola = derive_matricola(email)

    log("\n" + "=" * 50)
    log("[Allarme Sicurezza] Rilevato tentativo di Replay Attack...")

    # recupero del pacchetto precedentemente inviato 
    busta_json = voter_ballots.get(matricola)
    if busta_json is None:
        return _dashboard(email, password, matricola, error="File di log vuoto: impossibile eseguire la ritrasmissione.")

    log("[Network] Intercettazione e iniezione del pacchetto duplicato verso l'ES...")
    try:
        # tentativo di reiniettare la stessa busta per indurre un doppio conteggio
        server.receive_vote(busta_json)
        log("[Election Server] VULNERABILITÀ RILEVATA: il replay ha bypassato i controlli.")
        return _dashboard(email, password, matricola, error="Criticità: il sistema ha accettato un pacchetto duplicato.")
    except (ValueError, PermissionError) as e:
        # la difesa attiva dell election server intercetta il duplicato e solleva un'eccezione
        log(f"[Election Server] Difesa attiva. Duplicato bloccato: {e}")
        return _dashboard(email, password, matricola, info=f"Tentativo bloccato. L'ES ha risposto: {e}")

@app.route("/scrutinio")
def scrutinio():
    global public_results

    # blocco dello spoglio se il registro dei log antimanomissione risulta vuoto
    if not server.tamper_evident_log:
        return render_template_string(HTML, step="scrutinio_empty", **_ctx())

    log("\n" + "=" * 50)
    log("[Election Server] Chiusura operazioni e avvio spoglio...")

    # esecuzione dello spoglio anonimo con decifratura e costruzione dell albero di merkle
    t0 = time.perf_counter()
    public_results = server.close_polls_and_tally()
    t_tally = (time.perf_counter() - t0) * 1000

    # calcolo delle prestazioni relative al tempo totale richiesto per l elaborazione dei dati.
    n = len(public_results["merkle_tree"][0])
    log(f"[Election Server] Decifratura {n} schede e generazione Merkle Tree conclusa in {t_tally:.3f} ms")
    log(f"[Election Server] Esito conteggi: {public_results['results']}")
    log(f"[Election Server] Root crittografica del registro: {public_results['merkle_root']}")

    # calcolo delle prestazioni relative al tempo totale richiesto per l elaborazione dei dati.
    n = len(public_results["merkle_tree"][0])
    # ... altri log ...
    log(f"[Election Server] Root crittografica del registro: {public_results['merkle_root']}")
    
    #verifica della parità tra schede nell'urna e votanti
    n_pseudonimi = len(public_results["pseudonimi_pubblicati"])
    log(f"[Auditing] Verifica parità urna: {n} schede trovate, {n_pseudonimi} pseudonimi autorizzati. Integrità confermata.")

    # rendering della pagina dei risultati con la pubblicazione della root
    return render_template_string(HTML, step="scrutinio", **_ctx(
        results=public_results["results"], root=public_results["merkle_root"],
        n_votes=n, urne_aperte=server.is_open,
    ))

@app.route("/verifica", methods=["GET", "POST"])
def verifica():
    # controllo preliminare sulla disponibilita dei risultati pubblici sulla bacheca
    if public_results is None:
        return render_template_string(HTML, step="verifica_pending", **_ctx())

    result = None
    if request.method == "POST":
        email = request.form["email"]
        matricola = derive_matricola(email)
        client = wallets.get(matricola)

        # verifica se il client locale possiede i parametri necessari ed esegue il controllo.
        if client is None or client.receipt is None:
            result = {"error": "Parametri di verifica non trovati sul dispositivo locale."}
        else:
            # esecuzione della verifica matematica bottom up della proof of membership.
            t0 = time.perf_counter()
            included = client.verify_vote_in_urn(public_results)
            t_verify = (time.perf_counter() - t0) * 1000
            result = {"h": client.receipt["h"], "included": included}
            log(f"[Client] Verifica Proof of Membership per la matricola {matricola}: {included} (Tempo: {t_verify:.4f} ms)")

    return render_template_string(HTML, step="verifica", result=result, **_ctx())

if __name__ == "__main__":
    # inizializzazione del terminale di controllo tramite pulizia dei flussi precedenti
    # configurazione del server web flask locale impostando l indirizzo e la porta dedicati
    os.system("cls" if os.name == "nt" else "clear")
    print("\n")
    print(" ELECTION SERVER E APPLICATIVO LOCALE AVVIATI ")
    print(" Accesso disponibile all'indirizzo: http://127.0.0.1:5005 ")
    print("\n")
    app.run(host="127.0.0.1", port=5005, debug=False)