# ====================== LEGGIMI PRIMA DI CONTINUARE ===========================
#
# NOTA 1: per le variabili a stringa 'raw' (quelle aperte e chiuse con 3 apici),
# inserire i dati seguendo il formato indicato. Andare a capo per ogni cosa
# singola (es. una subnet per riga, lo stesso per interfacce, routing table,
# pacchetti)
# 
# NOTA 2: nel formato, i parametri scritti <cosi> sono opzionali. Si possono
# non aggiungere, a meno che l'esercizio non li fornisca
#
# ==============================================================================

# --- SUBNETTING --- #

# ======================== NOTE SUL SUBNETTING =================================
# - SE 2 RETI IP SONO SEBARATE DA UN BRIDGE O DA UN DISPOSITIVO DI LIVELLO
# INFERIORE SONO LA STESSA RETE IP SE SONO INVECE SEPARATE DA UN ROUTER SONO
# RETI DIVERSE
# - ATTENZIONE, IN ALCUNI ESERCIZI SI POTREBBERO INCLUDERE LE INTERFACCE DEI
# ROUTER DEI P2P DIRETTAMENTE NELLE SUBNET, LEGGERE BENE IL TESTO
# ==============================================================================

ip_rete_base: str = "10.87.208.0"
netmask_cidr: int = 21
# es. di netmask: 24 sarebbe netmask /24 ossia 255.255.255.0

# formato: nome_sottorete,numero_host
# esempio: net-A,500
subnets: str = """
netA,700
netB,500
netC,100
netD,60
netE,60
netF,40
netG,25
netH,20
netI,10
netL,10
"""

# formato: nome_connessione_ptp
# esempio: link-1
connessioni_punto_punto: str = """
pp1
pp2
pp3
pp4
pp5
"""




# --- ROUTING --- #

# format: nome,ip,netmask,MTU
# esempio: eth0,131.175.84.3,255.255.254.0,800
interfaces: str = """
eth0,131.175.192.1,255.255.192.0,1500
eth1,131.175.128.1,255.255.192.0,1500
wifi0,128.10.10.1,255.255.255.0,500
"""

# format: ip_rete,netmask,next_hop
# esempio: 121.30.167.212,255.255.255.252,131.175.86.171
routing_table: str = """
131.175.32.0,255.255.224.0,128.10.10.123
131.175.64.0,255.255.192.0,131.175.220.14
131.175.144.0,255.255.240.0,128.10.10.123
131.0.0.0,255.0.0.0,128.10.10.123
0.0.0.0,0.0.0.0,131.175.145.13
"""

# format: ip_destinazione,dimensione,<bit_dont_fragment>,<TTL>,<interfaccia_di_entrata>
# esempio: 15.255.255.255,56,1,21,eth1
pacchetti: str = """
175.123.12.123,500,1,999,wifi0
131.175.64.12,180,1,999,eth1
131.175.65.120,180,1,999,eth0
131.175.192.1,200,1,999,eth1
131.175.228.13,1200,1,999,eth1
131.175.191.255,400,1,999,eth0
131.175.33.12,1200,0,999,eth0
0.0.0.0,1300,1,999,eth1
"""