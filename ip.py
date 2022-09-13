from iputils import *

tabela_encaminhamento = []

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.protocolo = IPPROTO_TCP


    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            # prepara o encaminhamento dos pacotes para o proximo hop
            next_hop = self._next_hop(dst_addr)
            ttl -= 1

            # caso o pacote possa ser enviado para outro hop

            if ttl > 0:
                encaminha_datagrama = make_ipv4_header(payload, src_addr, dst_addr, self.protocolo, ttl) + payload
                self.enlace.enviar(encaminha_datagrama, next_hop)

            else:   # TTL <= 0
                    #Encaminha um datagrama com o erro ICMP (Internet Control Message Protocol)
                segmento = datagrama[:28]
                # Type = 11 (8 bits) | Code = 0 (8 bits) | Checksum (16 bits)

                icmp_type = 11
                icmp_code = 0
                icmp_unused = 0

                payload = struct.pack('!BBHI', icmp_type,  icmp_code, 0, icmp_unused) + segmento
                icmp_checksum = calc_checksum(payload)
                payload = struct.pack('!BBHI', icmp_type,  icmp_code, icmp_checksum, icmp_unused) + segmento

                self.protocolo = IPPROTO_ICMP
                encaminha_datagrama = make_ipv4_header(payload, self.meu_endereco, src_addr, self.protocolo) + payload
                self.enlace.enviar(encaminha_datagrama, self._next_hop(src_addr))
                self.protocolo = IPPROTO_TCP


    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.

        #print('IP DESTINO: ')
        #print(dest_addr)
        #print('***************')

        global tabela_encaminhamento

        if not tabela_encaminhamento:
            return None  # retorna vazio se a tabela de encaminhamento estiver vazia

        lista_possivel_proximo = []

        for item in tabela_encaminhamento:
            # procura os possiveis enderecos destino
            # se um IP conhecido da tabela de encaminhamento for igual ao endereço destino
            (possivel_proximo, prefixo) = item[0].split("/") # possivel_proximo = IP sem o prefixo
            #print('IP Tabela Encaminhamento: ')
            #print(item)
            #print('*******************')
            # se o IP conhecido não for igual ao endereço destino, encontrar um endereco mais proximo

            possivel_proximo_split = possivel_proximo.split(".") #divide a string IP em cada ponto (x.y.z.w)
            ip_binario = ""
            for i in possivel_proximo_split:
                ip_binario += "{0:08b}".format(int(i)) # para cada item, converte em um binario de 8 digitos e concatena em uma string

            dest_addr_split = dest_addr.split(".")
            dest_addr_binario = ""
            for i in dest_addr_split:
                dest_addr_binario += "{0:08b}".format(int(i)) # converte o endereco destino em binario


            if dest_addr_binario[:int(prefixo)] == ip_binario[:int(prefixo)]: # se o começo do ip destino tiver identicamente os mesmos bits do IP conhecido
                lista_possivel_proximo.append((item[1], int(prefixo))) # adiciona o IP conhecido a lista de possivel proximo e qual o prefixo da tabela

        if not lista_possivel_proximo:
            return None

        ordena_lista_possivel_proximo = sorted(lista_possivel_proximo, key=lambda tup: tup[1], reverse = True) # ordena a lista de possiveis proximos pelo maior prefixo
        ip_next_hop = ordena_lista_possivel_proximo[0]
        #print('Lista possiveis proximos: ')
        #print(ordena_lista_possivel_proximo)
        #print('**********************')
        return ip_next_hop[0]


    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.

        global tabela_encaminhamento
        tabela_encaminhamento = []

        for item in tabela:
            ip_local = item[0]
            ip_proximo = item[1]
            tabela_encaminhamento.append((ip_local, ip_proximo))

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.
        datagrama = make_ipv4_header(segmento, self.meu_endereco, dest_addr, self.protocolo) + segmento

        self.enlace.enviar(datagrama, next_hop)

def make_ipv4_header(segmento, src_addr, dest_addr, protocolo, ttl=64):
    version = 4 << 4
    ihl = 5
    vihl = version | ihl
    dscp = 0 << 6
    ecn = 0
    dscpecn = dscp | ecn
    total_len = len(segmento) + 20
    identification = 0
    flagsfrag = 0
    ttl = ttl
    proto = protocolo
    s = int.from_bytes(str2addr(src_addr), "big")
    d = int.from_bytes(str2addr(dest_addr), "big")
    header = struct.pack('!BBHHHBBHII', vihl, dscpecn, total_len,
        identification, flagsfrag, ttl, proto, 0, s, d)
    checksum = calc_checksum(header)
    novo_header = struct.pack('!BBHHHBBHII', vihl, dscpecn, total_len, identification,
                    flagsfrag, ttl, proto, checksum, s, d)
    return novo_header
