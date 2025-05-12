#   ██████╗ ███████╗██████╗ ████████╗██╗  ██╗██╗   ██╗ ██████╗ ██╗   ██╗██████╗ ███████╗
#   ██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██║  ██║╚██╗ ██╔╝██╔═══██╗██║   ██║██╔══██╗██╔════╝
#   ██████╔╝█████╗  ██████╔╝   ██║   ███████║ ╚████╔╝ ██║   ██║██║   ██║██████╔╝█████╗  
#   ██╔══██╗██╔══╝  ██╔══██╗   ██║   ██╔══██║  ╚██╔╝  ██║   ██║██║   ██║██╔══██╗██╔══╝  
#   ██████╔╝███████╗██║  ██║   ██║   ██║  ██║   ██║   ╚██████╔╝╚██████╔╝██████╔╝███████╗
#   ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═════╝ ╚══════╝
# + CSV patch by SolarCTP
 
try:
    import dati
except ImportError:
    print("Manca il file dati.py. Assicurati che sia nella stessa cartella di questo script")
    exit(1)

from my_csv import parse as csv_parse

#Classe di funzioni utile alla manipolazione degli indirizzi IP
class IP_functions:
    
    #Converte una stringa che rapresenta un indirizzo IP in un intero
    @staticmethod
    def ip_to_int(ip_str):
        #Creo la lista parts che al suo interno contiene gli elementi della stringa divisi laddove è presente un .
        #La funzione strip rimuove spazi all'inizio o alla fine della stringa
        parts = ip_str.strip().split('.')
        #Se le parti in cui è diviso l'indirizzo IP non sono quattro c'è un errore
        if len(parts) != 4:
            raise ValueError('L\'indirizzo deve avere 4 ottetti')
        value = 0
        #Ciclo per tutte le parti all'interno di parts
        for part in parts:
            #Tutte le parti devono essere dei numeri 
            if not part.isdigit():
                raise ValueError('Ogni ottetto deve essere numerico')
            #Converto la parte che sto analizzando in numero
            n = int(part)
            #Mi assicuro che il numero della parte che sto analizzando sia consentito
            if n < 0 or n > 255:
                raise ValueError('Ottetto fuori range (0‑255)')
            #Per ogni ottetto traslo a destra value di 8 posizioni e applico un or bit a bit con l'attuale ottetto che sto analizzando
            value = (value << 8) | n
        return value

    #Converte un indirizzo IP rappresentato da numeri interi in una stringa 
    @staticmethod
    def int_to_ip(ip_int):
        #Creo una lista vuota di ottetti
        octets = []
        #Per ogni shift in 24 16 8 0
        for shift in (24, 16, 8, 0):
            #Traslo a sinistra l'indirizzo di shift posizioni ed effettuo un and bit a bit con 0xFF
            #0xFF è la notazione esadecimale per 255 in decimale o 11111111 in binario
            n = (ip_int >> shift) & 0xFF
            octets.append(str(n))
        return '.'.join(octets)
    
    #Applica una netmask all'indirizzo IP intero inserito
    #In pratica effettua l'and bit a bit tra indirizzo IP e netmask
    @staticmethod
    def apply_netmask(ip_int, netmask_int):        
        return ip_int & netmask_int

    #Conta i bit a 1 nella netmask
    #Serve per vedere quale netmask è più specifica nel caso di necessità di disambiguazione della priorià delle rotte
    @staticmethod
    def prefix_length(netmask_int):
        #Converte la netmask da intero a binario e conta gli 1 che compaiono
        return bin(netmask_int).count("1")

    #Calcola l'indirizzo di broadcast noto l indirizzo ip e la netmask
    @staticmethod
    def prefix_to_ip(netmask_prefix):  
        # 0xFFFFFFFF è un numero intero con 32 uni 11111111.11111111.11111111.11111111
        # << (32 - netmask_prefix) trasla a sinistra gli 1 di (32 - netmask_prefix) posizioni
        # & 0xFFFFFFFF effettua un and bit a bit con la stringa di 32 uni per assicurarsi che il risutato abbia 32 bit
        return (0xFFFFFFFF << (32 - netmask_prefix)) & 0xFFFFFFFF

    #Calcola l'indirizzo di broadcast noto l indirizzo ip e la netmask
    @staticmethod
    def broadcast_address(network, netmask_int):
        #Indirizzo di broadcast della sottorete dell'interfaccia del router
        #~netmask_int inverte la netmask ponendo a 1 tutti gli 0 e a 0 tutti gli 1
        #viene effettuato un and bit a bit tra la netmask invertita e 0xFFFFFFFF che corrisponde in decimale a 255.255.255.255
        #Questo per mantenere solo i primi 32 bit dato che ~ in python potrebbe generare dei numeri negativi
        #Dopo viene effettuato un or bit a bit tra l indirizzo ip e la netmask invertita trovando così l'indirizzo di broadcast della sottorete 
        broadcast = network | (~netmask_int & 0xFFFFFFFF)
        return broadcast

def min_prefix_for_hosts(hosts):
    needed : int = hosts + 2  # Include network and broadcast
    bits : int = 0
    while 2**bits < needed:
        bits += 1
    return 32 - bits

class Subnet:
    def __init__(self, name, base_ip_int, prefix_len):
        self.name : str = name
        self.base_ip_int : int = base_ip_int
        self.prefix_len : int = prefix_len        
        self.broadcast_ip_int : int = IP_functions.broadcast_address(base_ip_int, IP_functions.prefix_to_ip(prefix_len))

class Tree_Node:
    def __init__(self, subnet):
        self.subnet : Subnet = subnet
        self.left : Subnet = None
        self.right : Subnet = None  
        self.allocated : bool = False  # è stato assegnato a una richiesta?
        self.divided : bool = False

class SubnetAllocator:
    def __init__(self, network_ip, prefix_len):
        self.network : int = IP_functions.ip_to_int(network_ip)
        self.network_prefix : int = prefix_len
        self.subnets_list : list[tuple[str, int]] = []
        self.p2p_links_list : list[str]= []
        self.requests_list : list[tuple[str, int]] = [] 

        self.root : Tree_Node = Tree_Node(Subnet("root", self.network, self.network_prefix))

    def suddividi_nodo(self, node, prefix_required):
        print(f"Divido il nodo {IP_functions.int_to_ip(node.subnet.base_ip_int)}/{node.subnet.prefix_len} in:")
        base_ip : int = node.subnet.base_ip_int
        new_prefix : int = node.subnet.prefix_len + 1
        left_subnet : Subnet = Subnet("temp", base_ip, new_prefix)
        right_subnet : Subnet = Subnet("temp", base_ip + 2**(32 - new_prefix), new_prefix)
        node.left = Tree_Node(left_subnet)
        node.right = Tree_Node(right_subnet)
    
        # Segniamo il nodo come diviso
        node.divided = True
        print(f"Divisione 1: {IP_functions.int_to_ip(left_subnet.base_ip_int)}/{left_subnet.prefix_len}")
        print(f"Divisione 2: {IP_functions.int_to_ip(right_subnet.base_ip_int)}/{right_subnet.prefix_len}")
        print("Dopo la divisione i nodi disponibili nel nostro albero sono:")
        self.stampa_nodi_liberi(self.root)
        print("")
        # Ora che abbiamo diviso, proseguiamo la ricerca nel figlio sinistro
        return self.trova_nodo_adatto(node.left, prefix_required)

    def trova_nodo_adatto(self, node, prefix_required):

        # Caso 1: nodo nullo
        if node is None:
            return None

        # Caso 2: nodo già allocato
        if node.allocated:
            return None

        # Caso 3: nodo diviso → vai nei figli
        if node.left is not None or node.right is not None:         # Che equivale a verificare if node.divided
            left_result = self.trova_nodo_adatto(node.left, prefix_required)
            if left_result:
                return left_result
            return self.trova_nodo_adatto(node.right, prefix_required)

        # Caso 4: nodo foglia libera
        if node.subnet.prefix_len == prefix_required:
            node.allocated = True
            return node
        elif node.subnet.prefix_len < prefix_required:
            return self.suddividi_nodo(node, prefix_required)
        else:
            return None  # Nodo troppo piccolo

    def stampa_nodi_liberi(self, node, livello=0):
        if node is None:
            return

        # Se il nodo è una foglia (niente figli) e non è allocato, lo stampiamo
        if node.left is None and node.right is None and not node.allocated:
            indent : str = "  " #* livello
            subnet : Subnet = node.subnet
            colore_libero : str = "\033[33m"
            colore_reset : str =  "\033[0m"
            print(f"{colore_libero}{indent}- {IP_functions.int_to_ip(subnet.base_ip_int)}/{subnet.prefix_len} [LIBERO]{colore_reset}")

        # Altrimenti esplora i figli (anche se allocati, perché sotto potrebbero esserci nodi liberi)
        if node.left:
            self.stampa_nodi_liberi(node.left, livello + 1)
        if node.right:
            self.stampa_nodi_liberi(node.right, livello + 1)
    
    def alloca(self):

        risultato : Subnet = []

        for sottorete in self.requests_list:

            prefix_required : int = min_prefix_for_hosts(sottorete[1])
            print(f"Cerchiamo ora un subnetting adeguato per {sottorete[0]}")
            print(f"{sottorete[0]} deve soddisfare {sottorete[1]} hosts, quindi {sottorete[0]} deve avere {sottorete[1]} + 2 = {sottorete[1] + 2} indirizzi")
            print("Questo per includere anche indirizzo di broadcast diretto e indirizzo di rete")
            print(f"Calcoliamoci il numero di bit che ci servono per indirizzare {sottorete[1]} hosts della rete {sottorete[0]} 2^n ≥ {sottorete[1] + 2}")
            print(f"In questo caso n = {32 - prefix_required}")
            print(f"La lunghezza del prefisso della netmask sarà dunque 32 - n = {prefix_required}")
            print(f"Ne segue che abbiamo bisogno di una sottorete con netmask /{prefix_required} per subnettare {sottorete[0]}\n")
            
            #Cerchiamo nell albero delle subnet un nodo adatto da allocare
            nodo_trovato : Tree_Node = None
            nodo_trovato = self.trova_nodo_adatto(self.root, prefix_required)
            
            if nodo_trovato is None:
                raise ValueError(f"Spazio esaurito per {sottorete[0]}")
            nodo_trovato.allocated = True  
            nodo_trovato.subnet.name = sottorete[0]
            risultato.append(Subnet(sottorete[0], nodo_trovato.subnet.base_ip_int, nodo_trovato.subnet.prefix_len))
            print(f"Abbiamo quindi trovato una sottorete /{prefix_required} per {sottorete[0]} da {2**(32 - prefix_required)} - 2 hosts utilizzabili che allochiamo a {sottorete[0]}")
            print ("Nodo preso per " + sottorete[0] +" "+ IP_functions.int_to_ip(nodo_trovato.subnet.base_ip_int) +"/"+ str(nodo_trovato.subnet.prefix_len))
            print("stampo la lista di nodi disponibili")
            self.stampa_nodi_liberi(self.root)
            print("")
              
        print("Le sottoreti rimaste inutilizzate sono: ")
        self.stampa_nodi_liberi(self.root)      
        print("") 
        print("Il risultato finale delle reti subnettate è il seguente: \n")
        for rete in risultato:       
            print(("-" * (rete.prefix_len - self.network_prefix)) + rete.name + ":" + IP_functions.int_to_ip(rete.base_ip_int) + "/" + str(rete.prefix_len) + " - Broadcast: " + IP_functions.int_to_ip(rete.broadcast_ip_int))

    def add_subnet(self, subnet_name, n_hosts):
        self.subnets_list.append((subnet_name,n_hosts))
    
    def add_p2p_link(self, p2p_name):
        self.p2p_links_list.append(p2p_name)

    #Genero la lista complessiva delle subnet e link p2p richiesti
    def generate_requests_list(self):
        self.requests_list = self.subnets_list
        #Considero i link p2p come se fossero semplici sottoreti da 2 host
        for i in self.p2p_links_list:
            self.requests_list.append((i, 2))

        # Ordino le sottoreti inserite dalla più grande alla più piccola in termini di numero di hosts
        self.requests_list = sorted(self.requests_list, key=lambda x: -x[1])

def print_inserted_data(rete_base, prefisso, allocator):

    L_NAME : int = 20 #larghezza totale del campo nome
    L_HO : int = 20 #larghezza totale del campo hosts

    # Intestazione
    print(f"Rete inserita: {rete_base} / {prefisso} \n")
    # :> allinea il testo a destra mentre :< lo allinea a sinistra
    # {L_ID} {L_IP} {L_LNG} {L_DF} impostano la lunghezza totale del campo caratteri
    print(f"{'Subnet':^{L_NAME}} | {'Hosts':^{L_HO}}")
    # Stampa "-" tante volte pari a L_NAME + L_HO + 5
    print("-" * (L_NAME + L_HO + 5))

    # Dati
    for subnet in allocator.requests_list:        
        print(f"{subnet[0]:^{L_NAME}} | {subnet[1]:^{L_HO}}")
        print("-" * (L_NAME + L_HO + 5))
    print ("\n")

def print_result(node, prefix="", is_last=True, is_root=True):
    if node is None:
        return
    
    # ├── o └── per disegnare l'albero
    if is_root:
        ramo = ""
    else:
        if is_last:
            ramo = "└── "
        else:
            ramo = "├── "

    # Dati della subnet
    subnet : Subnet = node.subnet
    ip_str : str = IP_functions.int_to_ip(subnet.base_ip_int)
    broadcast_str : str = IP_functions.int_to_ip(subnet.broadcast_ip_int)

    # Colori ANSI
    RESET : str = "\033[0m"
    GREEN : str = "\033[92m"
    BLUE : str = "\033[96m"
    YELLOW : str = "\033[33m"

    # Stato logico del nodo
    if node.allocated:
        stato = "ALLOCATO"
        colore = GREEN
        print(f"{prefix}{ramo}{colore}{ip_str}/{subnet.prefix_len} - {2**(32 - subnet.prefix_len)}-2={2**(32 - subnet.prefix_len) - 2} hosts - {subnet.name} - broadcast: {broadcast_str} [{stato}] {RESET}")
    elif node.left or node.right:
        stato = "DIVISO"
        colore = BLUE
        print(f"{prefix}{ramo}{colore}{ip_str}/{subnet.prefix_len} - {subnet.name} [{stato}] {RESET}")
    else:
        stato = "LIBERO"
        colore = YELLOW
        print(f"{prefix}{ramo}{colore}{ip_str}/{subnet.prefix_len} - {subnet.name} [{stato}] {RESET}")

    # Calcolo nuovo prefisso per indentazione figli
    children = [child for child in [node.left, node.right] if child is not None]
    for i, child in enumerate(children):
        is_last_child = i == len(children) - 1
        if is_root:
            new_prefix = prefix
        else:
            if is_last:
                new_prefix = prefix + "    "
            else:
                new_prefix = prefix + "│   "
        print_result(child, new_prefix, is_last_child, False)

# ------------------------
# Inserimento Dati
# ------------------------

rete_base : str  = dati.ip_rete_base
prefisso : int = dati.netmask_cidr

allocator : SubnetAllocator = SubnetAllocator(rete_base, prefisso)

### SE 2 RETI IP SONO SEBARATE DA UN BRIDGE O DA UN DISPOSITIVO DI LIVELLO INFERIORE SONO LA STESSA RETE IP
### SE SONO INVECE SEPARATE DA UN ROUTER SONO RETI DIVERSE

### ATTENZIONE IN ALCUNI ESERCIZI SI POTREBBERO INCLUDERE LE INTERFACCE DEI ROUTER DEI P2P DIRETTAMENTE NELLE SUBNET, LEGGERE BENE IL TESTO

for line in csv_parse(dati.subnets):
    allocator.add_subnet(line[0], int(line[1]))

for line in csv_parse(dati.connessioni_punto_punto):
    allocator.add_p2p_link(line[0])


#Creo la lista complessiva delle subnt richieste, nota bene posso farlo solo dopo aver inserito i dati
allocator.generate_requests_list()

print_inserted_data(rete_base, prefisso, allocator)

allocator.alloca()
print("\nChe scritto sotto forma di albero diventa:\n")
print_result(allocator.root)

input("Press any key to continue...")
