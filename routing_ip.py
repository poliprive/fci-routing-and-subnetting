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

from _csv import parse as csv_parse

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

#Classe per la definizione delle interfacce del router
class Interface:
    def __init__(self, name, ip_str, netmask_str, mtu):
        self.name : str = name
        #L'indirizzo IP intero associato all'interfaccia del router
        self.ip : int = IP_functions.ip_to_int(ip_str)
        #La netmask associata all'indirizzo ip dell'interfaccia del router
        self.netmask : int = IP_functions.ip_to_int(netmask_str)
        self.mtu : int = mtu
        #Indirizzo della sottorete dell'interfaccia del router calcolato applicando la propria netmask al proprio indirizzo IP
        self.network : int = IP_functions.apply_netmask(self.ip, self.netmask)
        #Indirizzo di broadcast della sottorete dell'interfaccia del router
        #~self.netmask inverte la netmask ponendo a 1 tutti gli 0 e a 0 tutti gli 1
        #viene effettuato un and bit a bit tra la netmask invertita e 0xFFFFFFFF che corrisponde in decimale a 255.255.255.255
        #Questo per mantenere solo i primi 32 bit dato che ~ in python potrebbe generare dei numeri negativi
        #Dopo viene effettuato un or bit a bit tra l indirizzo di rete e la netmask invertita trovando così l'indirizzo di broadcast della sottorete 
        self.broadcast : breakpoint = self.network | (~self.netmask & 0xFFFFFFFF)

#Classe per definire una riga della tabella di routing del router
class Route:
    def __init__(self, identifier, network_str, netmask_str, next_hop_str, interface):
        self.identifier : int = identifier 
        #indirizzo di rete della riga
        self.network : int = IP_functions.ip_to_int(network_str)
        #netmask della riga
        self.netmask : int = IP_functions.ip_to_int(netmask_str)
        #next hope della riga
        self.next_hop : int = IP_functions.ip_to_int(next_hop_str)
        self.interface : Interface = interface 

#Classe per definire un pacchetto da analizzare
class Packet:
    def __init__(self, identifier, dest_ip_str, length, dont_fragment=False, TTL = 9999, input_interface = None):
        self.identifier : int = identifier
        #indirizzo di destinazione del pacchetto
        self.dest_ip : int = IP_functions.ip_to_int(dest_ip_str)
        #lunghezza in byte del pacchetto
        self.length : int = length
        #dont fragment flag
        self.dont_fragment : bool = dont_fragment
        #Impostato di default a un valore molto alto prossimo a infinito
        self.TTL : int = TTL
        #Se specificata l'interfaccia di ingresso
        self.input_interface : str = input_interface

#Classe per definire il router
class Router:
    def __init__(self):
        self.RED : str = "\033[91m"
        self.GREEN : str= "\033[92m"
        self.RESET : str= "\033[0m"

        #Lista delle interfacce di uscita del router
        self.interfaces : list[Interface]= []
        #Lista delle righe della tabella di inoltro del router
        self.routes : list[Route]= []
        #Lista dei risultati
        #E una lista di tuple con all'interno (identifier del pacchetto, flag dell'intoltro diretto, riga dell'inoltro indiretto, interfaccia di uscita, commento)
        self.results : list[(int, bool, int, str, str)]= []
    
    #Metodo per aggiungere un interfaccia al router
    def add_interface(self, name, ip, netmask, mtu):
        self.interfaces.append(Interface(name, ip, netmask, mtu))
    
    #Metodo per aggiungere una riga alla tabella di inoltro del router
    def add_route(self, network, netmask, next_hop):        
        
        interface : Interface = None

        next_hop_int = IP_functions.ip_to_int(next_hop)

        #Scorre per tutte le interfacce
        for iface in self.interfaces:
            #Se il netowork del next_hop ottenuto applicando la netmask dell'interfaccia è uguale al netowork dell'interfaccia allora assegna l'interfaccia
            if IP_functions.apply_netmask(next_hop_int, iface.netmask) == iface.network:
                interface = iface
                break

        # Se non trovata, errore
        if not interface:
            raise ValueError(f"Errore: impossibile determinare l'interfaccia per la rotta verso {network}/{netmask}")
            return

        numerorighe = len(self.routes)
        self.routes.append(Route(numerorighe + 1,network, netmask, next_hop, interface))

    def route_packet(self, packet):

        interfaccia_di_ingresso : Interface = None;
        for iface in self.interfaces:
            if packet.input_interface == iface.name:
                interfaccia_di_ingresso = iface

        is_direct_forwarding : bool= False
        current_output_interface : Interface = None
        current_indirect_forwarding_raw : int = None
        is_direct_broadcast : bool = False

        #Trasformo a intero l'indirizzo ip di destinazione
        dest_ip : int = packet.dest_ip
        print (f"Analizziamo il pacchetto {packet.identifier}") 
        
        #Diminuisco di 1 il TTL
        print(f"Diminuisco il time to leave: TTL - 1 = {packet.TTL - 1}")
        packet.TTL -= 1
        
        #Controllo se il pacchetto è destinato al router
        for iface in self.interfaces:
            if packet.dest_ip == iface.ip:
                print(f"{self.GREEN}Il pacchetto ha come IP di destinazione {IP_functions.int_to_ip(packet.dest_ip)} che è uguale a {IP_functions.int_to_ip(iface.ip)}, dell'interfaccia {iface.name} \nDi conseguenza il pacchetto ha come destinazione finale il Router e quindi viene passato a livello 4{self.RESET}")
                self.results.append((packet.identifier,False, None, None, "Passato a livello superiore"))
                return
        print(f"{self.RED}{IP_functions.int_to_ip(packet.dest_ip)} è diverso da tutti gli indirizzi ip delle interfacce, quindi il pacchetto non è destinato al router{self.RESET}")

        #Controllo se il pacchetto è di tipo broadcast limitato      
        if dest_ip == IP_functions.ip_to_int("255.255.255.255"):
            print(f"{self.GREEN}Il pacchetto è di broadcast limitato. Pacchetto inviato a livello 4 e non inoltrato MAI{self.RESET}")
            self.results.append((packet.identifier,False, None, None, "Broadcast limitato, Passato a livello superiore"))
            return
        print(f"{self.RED}Il pacchetto non è di broadcast limitato, perchè {IP_functions.int_to_ip(dest_ip)} è diverso da 255.255.255.255{self.RESET}")

        #Controllo se il pacchetto è di tipo 0.0.0.0     
        if dest_ip == IP_functions.ip_to_int("0.0.0.0"):
            print(f"{self.GREEN}Il pacchetto è di tipo 0.0.0.0 qunidi viene scartato{self.RESET}")
            self.results.append((packet.identifier,False, None, None, "Pacchetto scartato"))
            return
        print(f"{self.RED}Il pacchetto non è di tipo 0.0.0.0{self.RESET}")

        #Controllo se il pacchetto è di tipo unicast limitato     
        # Se il NET ID = 0 
        if (IP_functions.apply_netmask(dest_ip, interfaccia_di_ingresso.netmask) == 0) and (dest_ip & (~interfaccia_di_ingresso.netmask & 0xFFFFFFFF) != 0):
            #Se l'host id del pacchetto è uguale all'host id della rete di provenienza allora passa ai livelli superiori se no inoltro diretto
            print(dest_ip & (~interfaccia_di_ingresso.netmask & 0xFFFFFFFF))
            print(interfaccia_di_ingresso.ip & (~interfaccia_di_ingresso.netmask & 0xFFFFFFFF))
            if (dest_ip & (~interfaccia_di_ingresso.netmask & 0xFFFFFFFF)) == (interfaccia_di_ingresso.ip & (~interfaccia_di_ingresso.netmask & 0xFFFFFFFF)):
                print(f"{self.GREEN}Il pacchetto è di unicast limitato, ma l'indirizzo di host coincite con l'interfaccia del router e quindi viene passato ai livlli superiori{self.RESET}")
                self.results.append((packet.identifier,False, None, None, "Passato ai livelli superiori"))
                return
            else:           
                print(f"{self.GREEN}Il pacchetto è di unicast limitato. Viene inoltrato direttamente sull'intrefaccia di provenienza{self.RESET}")
                self.results.append((packet.identifier,True, None, interfaccia_di_ingresso.name, "Unicast limitato"))
                return
        print(f"{self.RED}Il pacchetto non è di unicast limitato, perchè il NET ID è diverso da 0{self.RESET}")

        # Controlla per l'inoltro diretto
        print("Analizziamo le varie interfaccie per l'inoltro diretto:")
        for iface in self.interfaces:
                                   
            if IP_functions.apply_netmask(dest_ip, iface.netmask) == iface.network:
                print(f"{self.GREEN} *  {iface.name} Netmask /{IP_functions.prefix_length(iface.netmask)}{self.RESET}")
                print(f"{self.GREEN}    IP di destinazione è: {IP_functions.int_to_ip(dest_ip)} e effettuando un AND con una netmask /{IP_functions.prefix_length(iface.netmask)} otteniamo = {IP_functions.int_to_ip(IP_functions.apply_netmask(dest_ip, iface.netmask))}{self.RESET}")
                print(f"{self.GREEN}    Mentre l'indirizzo di rete di {iface.name} è {IP_functions.int_to_ip(iface.network)}{self.RESET}")
                print(f"{self.GREEN}Poichè i 2 indirizzi trovati coincidono il pacchetto {packet.identifier} può essere inoltrato direttamente su {iface.name}{self.RESET}")
                is_direct_forwarding = True
                current_output_interface = iface
            else:
                print(f"{self.RED} *  {iface.name} Netmask /{IP_functions.prefix_length(iface.netmask)}{self.RESET}")
                print(f"{self.RED}    IP di destinazione è: {IP_functions.int_to_ip(dest_ip)} e effettuando un AND con una netmask /{IP_functions.prefix_length(iface.netmask)} otteniamo = {IP_functions.int_to_ip(IP_functions.apply_netmask(dest_ip, iface.netmask))}{self.RESET}")
                print(f"{self.RED}    Mentre l'indirizzo di rete di {iface.name} è {IP_functions.int_to_ip(iface.network)}{self.RESET}")
        if  is_direct_forwarding == False:
            print(f"{self.RED}Il pacchetto non è inoltrabile direttamente su nessun interfaccia{self.RESET}")
        

        # Controlla se è un broadcast diretto su qualche interfaccia
        if is_direct_forwarding == True:
            if packet.input_interface == None:
                for iface in self.interfaces:
                    if dest_ip == iface.broadcast:
                        print(f"Pacchetto {packet.identifier} destinato a broadcast diretto su {iface.name}")
                        is_direct_broadcast = True
            else:
                for iface in self.interfaces:
                    if dest_ip == iface.broadcast:
                        if packet.input_interface == iface.name:
                            print(f"Pacchetto dovrebbe essere trasmesso in broadcast su {iface.name}, tuttavia la sua interfaccia di ingresso è anchessa {iface.name}, e quindi il pacchetto va passato i livelli superiori")
                            self.results.append((packet.identifier,False, None, None, "Broadcast diretto, Passato a livello superiore"))
                            return
                        else:
                            print(f"Pacchetto inviato in broadcast diretto su {iface.name}")   
                            is_direct_broadcast = False
        print(f"{self.RED}Il pacchetto non è di broadcast diretto su nessuna interfaccia{self.RESET}")

        # Controlla per l'inoltro indiretto      
        if(is_direct_forwarding == False and is_direct_broadcast == False):
            print("Analizziamo le corrispondenze nella tabella di routing per l'inoltro indiretto:")
            # Cerca la rotta più specifica (Longest Prefix Match)
            best_route = None
            best_prefix = -1

            for route in self.routes:
                if IP_functions.apply_netmask(dest_ip, route.netmask) == route.network:
                    print(f"{self.GREEN} *  Riga {route.identifier}: NetID intirizzo IP pacchetto {IP_functions.int_to_ip(IP_functions.apply_netmask(dest_ip, route.netmask))}, Network route {IP_functions.int_to_ip(route.network)} RISCONTRO POSITIVO{self.RESET}")
                    pl = IP_functions.prefix_length(route.netmask)
                    if pl > best_prefix:
                        best_route = route
                        best_prefix = pl
                else:
                    print(f"{self.RED} *  Riga {route.identifier}: NetID intirizzo IP pacchetto {IP_functions.int_to_ip(IP_functions.apply_netmask(dest_ip, route.netmask))}, Network route {IP_functions.int_to_ip(route.network)} RISCONTRO NEGATIVO{self.RESET}")
        
            if not best_route:
                print (f"{self.RED}Pacchetto {packet.identifier} scartato: nessuna rotta disponibile{self.RESET}")
                self.results.append((packet.identifier,is_direct_forwarding, current_indirect_forwarding_raw, current_output_interface.name, "Pacchetto scartato: nessuna rotta disponibile"))
                return  

            print(f"Seguendo il LPM il pacchetto dovrebbe proseguire per inoltro indiretto alla riga {best_route.identifier} \nVerso il next hop {IP_functions.int_to_ip(best_route.next_hop)} attraverso l'interfaccia {best_route.interface.name}")
            current_indirect_forwarding_raw = best_route.identifier
            current_output_interface = best_route.interface

        #Controllo il TTL
        if packet.TTL == 0:
            print(f"{self.RED}Il pacchetto ha TTL = 0 e quindi viene scartato{self.RESET}")
            self.results.append((packet.identifier,is_direct_forwarding, current_indirect_forwarding_raw, current_output_interface.name, "Pacchetto scartato: TTL = 0"))
            return
        elif packet.TTL > 0:
            print(f"{self.GREEN}Il pacchetto ha TTL > 0 quindi possiamo procedere{self.RESET}")

        # Controllo MTU e Don't Fragment
        if is_direct_forwarding:
            if packet.length > current_output_interface.mtu and packet.dont_fragment:
                print(f"{self.GREEN}Pacchetto {packet.identifier} scartato: DF attivo e dimensione {packet.length}B > MTU ({current_output_interface.mtu}B){self.RESET}")
                self.results.append((packet.identifier,is_direct_forwarding, current_indirect_forwarding_raw, current_output_interface.name, f"Pacchetto scartato: DF attivo e dimensione > MTU ({current_output_interface.mtu}B)"))
                return
            print(f"{self.GREEN}Pacchetto {packet.identifier} ha DF disattivato o dimensione {packet.length} < {current_output_interface.mtu}B ({current_output_interface.name} MTU) quindi si procede per inoltro diretto{self.RESET}")
            print(f"{self.GREEN}Pacchetto {packet.identifier} Inoltro diretto interfaccia {current_output_interface.name}{self.RESET}")        
        else: 
            if packet.length > best_route.interface.mtu and packet.dont_fragment:
                print(f"{self.GREEN}Pacchetto {packet.identifier} scartato: DF attivo e dimensione {packet.length}B > MTU ({best_route.interface.mtu}B){self.RESET}")
                self.results.append((packet.identifier,is_direct_forwarding, current_indirect_forwarding_raw, current_output_interface.name, f"Pacchetto scartato: DF attivo e dimensione > MTU ({best_route.interface.mtu}B)"))
                return
            print(f"{self.GREEN}Pacchetto {packet.identifier} ha DF disattivato o dimensione {packet.length} < {best_route.interface.mtu}B ({best_route.interface.name} MTU) quindi si procede per inoltro indiretto{self.RESET}")
            print(f"{self.GREEN}Pacchetto {packet.identifier} Inoltro indiretto riga {best_route.identifier} \nVerso l'indirizzo {IP_functions.int_to_ip(best_route.next_hop)} attraverso l'interfaccia {best_route.interface.name}{self.RESET}")        
        
        self.results.append((packet.identifier,is_direct_forwarding, current_indirect_forwarding_raw, current_output_interface.name, ""))
        
    def print_routed_packets(self):

        L_ID : int = 4
        L_DIRECT : int = 10
        L_INDIRECT_RAW : int = 13
        L_INTERFACE : int = 12
        L_COMMENT : int = 65
        # Intestazione
        print("Il risultato dell'inoltro è:\n")
        print(f"{'ID':>{L_ID}} | {'Inoltro':<{L_DIRECT}} | {'Riga inoltro':<{L_INDIRECT_RAW}} | {'Interfaccia':<{L_INTERFACE}} | {'Commento':<{L_COMMENT}}")
        print(f"{'':>{L_ID}} | {'diretto':<{L_DIRECT}} | {'indiretto':<{L_INDIRECT_RAW}} | {'':<{L_INTERFACE}} | {'':<{L_COMMENT}}")
        print("-" * (L_ID * 2 + L_DIRECT + L_INDIRECT_RAW + L_INTERFACE + L_COMMENT))

        # Dati
        for i in self.results:
            if i[1] == True:
                is_direct_view = "X"
            else:
                is_direct_view = ""
            if i[2] != None:
                indirect_raw_view = i[2]
            else:
                indirect_raw_view = ""
            if i[3] != None:
                interface_view = i[3]
            else:
                interface_view = ""
            if i[4] != None:
                comment_view = i[4]
            else:
                indirect_raw_view = ""
            print(f"{i[0]:>{L_ID}} | {is_direct_view:^{L_DIRECT}} | {indirect_raw_view:<{L_INDIRECT_RAW}} | {interface_view:<{L_INTERFACE}} | {comment_view:<{L_COMMENT}}")
            print("-" * (L_ID * 2 + L_DIRECT + L_INDIRECT_RAW + L_INTERFACE + L_COMMENT))
        print ("\n")

def print_interface_table(router):
    L_NA : int = 10 #larghezza totale del campo Nome
    L_IP : int = 17 #larghezza totale dei campi con indirizzi IP
    L_MTU : int = 17 #larghezza totale dei campo MTU
    # Intestazione
    print("le interfacce inserite sono:")
    # :> allinea il testo a destra mentre :< lo allinea a sinistra
    # {L_ID} {L_IP} {L_IF} impostano la lunghezza totale del campo caratteri
    print(f"{'Nome':<{L_NA}} | {'IP':<{L_IP}} | {'Netmask':<{L_IP}} | {'MTU':<{L_MTU}} | {'Rete':<{L_IP}}")
    # Stampa "-" tante volte pari a L_NA + L_IP * 3 + L_MTU + 12
    print("-" * (L_NA + L_IP * 3 + L_MTU + 16))

    # Dati
    for iface in router.interfaces:
        ip_view = IP_functions.int_to_ip(iface.ip)
        netmask_view = IP_functions.int_to_ip(iface.netmask)
        mtu_len_str = str(iface.mtu) + "B"
        network_view = str(IP_functions.int_to_ip(iface.network)) + "/" + str(IP_functions.prefix_length(iface.netmask))
        print(f"{iface.name:<{L_NA}} | {ip_view:<{L_IP}} | {netmask_view:<{L_IP}} | {mtu_len_str:<{L_MTU}} | {network_view:<{L_IP}}")
        print("-" * (L_NA + L_IP * 3 + L_MTU + 16))
    print ("\n")

def print_rounting_table(router):
    
    L_ID : int = 4 #larghezza totale del campo ID
    L_IP : int = 17 #larghezza totale dei campi con indirizzi IP
    L_IF : int = 20 #larghezza totale dei campo interface
    # Intestazione
    print("la tabella di routing inserita è:")
    # :> allinea il testo a destra mentre :< lo allinea a sinistra
    # {L_ID} {L_IP} {L_IF} impostano la lunghezza totale del campo caratteri
    print(f"{'ID':>{L_ID}} | {'Network':<{L_IP}} | {'Netmask':<{L_IP}} | {'NextHop':<{L_IP}} | {'Interface':<{L_IF}}")
    # Stampa "-" tante volte pari a L_ID + L_IP * 3 + L_IF + 5
    print("-" * (L_ID + L_IP * 3 + L_IF + 5))

    # Dati
    for routes in router.routes:
        network_view = IP_functions.int_to_ip(routes.network)
        netmask_view = IP_functions.int_to_ip(routes.netmask)
        nexthop_view = IP_functions.int_to_ip(routes.next_hop)
        print(f"{routes.identifier:>{L_ID}} | {network_view:<{L_IP}} | {netmask_view:<{L_IP}} | {nexthop_view:<{L_IP}} | {routes.interface.name:<{L_IF}}")
        print("-" * (L_ID + L_IP * 3 + L_IF + 5))
    print ("\n")

def print_packet_table(packets_list):

    L_ID : int = 4 #larghezza totale del campo ID
    L_IP : int = 17 #larghezza totale del campo IP di destinazione
    L_LNG : int = 17 #larghezza totale dei campo length
    L_DF : int = 12 #larghezza totale dei campo dont fragment
    # Intestazione
    print("I pacchetti che sono stati inseriti sono:")
    # :> allinea il testo a destra mentre :< lo allinea a sinistra
    # {L_ID} {L_IP} {L_LNG} {L_DF} impostano la lunghezza totale del campo caratteri
    print(f"{'ID':>{L_ID}} | {'IP Destinazione':<{L_IP}} | {'Length(B)':<{L_LNG}} | {'Dont fragment':<{L_DF}} | {'TTL':<{L_DF}} | {'Input Interface':<{L_DF}}")
    # Stampa "-" tante volte pari a L_ID + L_IP + L_LNG + L_DF * 3 + 20
    print("-" * (L_ID + L_IP + L_LNG + L_DF * 3 + 20))

    # Dati
    for pacchetto in packets_list:
        dest_ip_view = IP_functions.int_to_ip(pacchetto.dest_ip)
        packet_len_str = str(pacchetto.length) + "B"
        if pacchetto.input_interface == None:
            interface_view = ""
        else:
            interface_view = pacchetto.input_interface
        print(f"{pacchetto.identifier:>{L_ID}} | {dest_ip_view:<{L_IP}} | {packet_len_str:<{L_LNG}} | {pacchetto.dont_fragment:<{L_DF}} | {pacchetto.TTL:<{L_DF}} | {interface_view:<{L_DF}}")
        print("-" * (L_ID + L_IP + L_LNG + L_DF * 3 + 20))
    print ("\n")

def add_packet(router, packets_list, dest_ip, length, dont_fragment=False, TTL=9999, input_interface = None):
    identifier : int = len(packets_list)
    esiste_interfaccia : bool = True
    if input_interface != None:
        esiste_interfaccia = False
        for interfaccia in router.interfaces:
            if input_interface == interfaccia.name:
                esiste_interfaccia = True
    if esiste_interfaccia == False:
        raise ValueError("Interfaccia inserita inesistente")
        return
    packets_list.append(Packet(identifier + 1, dest_ip, length, dont_fragment, TTL, input_interface))

router : Router = Router()
pacchetti : list[Packet]= []

# ------------------------
# Inserimento Dati
# ------------------------

for line in csv_parse(dati.interfaces):
    router.add_interface(line[0], line[1], line[2], int(line[3]))

for line in csv_parse(dati.routing_table):
    router.add_route(*line)

for line in csv_parse(dati.pacchetti):
    add_packet(router, pacchetti, line[0], int(line[1]),
               bool(int(line[2])) if len(line) >= 3 else False,
               int(line[3]) if len(line) >= 4 else 9999,
               line[4] if len(line) >= 5 else None,
    )

print_interface_table(router)
print_rounting_table(router)
print_packet_table(pacchetti)

for p in pacchetti:
    router.route_packet(p)
    print("")
    BLUE = "\033[96m"
    RESET = "\033[0m"
    print(f"{BLUE}----------------------------------------------------------------------------------------------------------------{RESET}")
    print("")

router.print_routed_packets()

input("Press any key to continue...")



