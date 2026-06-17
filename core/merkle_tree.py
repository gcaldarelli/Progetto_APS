import hashlib
import random

def sha256_str(data: str) -> str:
    # calcolo dell'hash SHA-256 standard, restituito in formato esadecimale
    return hashlib.sha256(data.encode("utf-8")).hexdigest()

def build_shuffled_merkle_tree(data_list: list[str]) -> tuple[str, list[list[str]], list[str]]:
    # Costruzione dell'Albero di Merkle per la verificabilità universale
    # include una fase preliminare di shuffling per rafforzare lo pseudoanonimato.
    if not data_list:
        raise ValueError("Impossibile generare l'albero: registro delle transazioni vuoto.")

    # Permutazione casuale uniforme 
    # Questa operazione distrugge l'ordine temporale di arrivo dei pacchetti.
    # Serve a mitigare i Timing Attacks impedendo a un intercettatore di associare un voto a un utente in base all'orario di invio.
    shuffled_list = data_list.copy()
    random.shuffle(shuffled_list)

    # Costruzione dell'Albero di Merkle (Bottom-Up)
    # Le foglie corrispondono agli hash dei ciphertext anonimi presenti nell'urna
    tree = [[sha256_str(d) for d in shuffled_list]]

    while len(tree[-1]) > 1:
        level = tree[-1]
        if len(level) % 2 == 1:
            level = level + [level[-1]]  # Duplicazione dell'ultimo nodo se il livello è dispari
        tree.append([
            sha256_str(level[i] + level[i + 1])
            for i in range(0, len(level), 2)
        ])

    # Ritorna la Merkle Root, la struttura completa e la lista permutata
    return tree[-1][0], tree, shuffled_list

def generate_proof_by_hash(target_hash: str, tree: list[list[str]]) -> list[tuple[str, str]]:
    # Generazione della Proof of Membership per la verificabilità individuale.
    # Estrae il cammino crittografico minimo necessario per risalire dalla singola 
    # foglia (la ricevuta in possesso dell'elettore) fino alla Merkle Root.
    leaves = tree[0] # estrazione del livello base dell albero che contiene tutte le foglie. rappresenta il registro pubblico contenente gli hash dei ciphertext anonimi.
    
    #controlla se l'hash della ricevuta è tra le foglie
    if target_hash not in leaves:
        raise ValueError("Incongruenza crittografica: hash della ricevuta non trovato nell'urna.")
    
    #recupero dell indice esatto della foglia all interno del livello base.
    leaf_index = leaves.index(target_hash)
    
    #inizializzazione della lista che ospitera la proof of membership.
    proof = []
    index = leaf_index

    for level in tree[:-1]:  # Iterazione fino alla radice esclusa
        if len(level) % 2 == 1:
            level = level + [level[-1]]

        sibling_index = index ^ 1
        position = "right" if sibling_index > index else "left"
        proof.append((position, level[sibling_index]))
        index //= 2

    return proof

def verify_proof(leaf_hash: str, proof: list[tuple[str, str]], root: str) -> bool:
    # Validazione locale della Proof of Membership.
    # L'applicativo client ricalcola iterativamente la catena di hash concatenando 
    # il nodo corrente con il nodo "fratello" fornito dalla prova.
    # Se l'hash finale coincide con la root pubblica, l'inclusione è dimostrata matematicamente.
    current = leaf_hash 

    for position, sibling in proof:
        if position == "right":
            # Il nodo fratello è a destra: concateniamo current + sibling
            current = sha256_str(current + sibling)
        else:
            # Il nodo fratello è a sinistra: concateniamo sibling + current
            current = sha256_str(sibling + current)

    return current == root