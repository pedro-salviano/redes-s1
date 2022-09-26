import asyncio
from collections import namedtuple
from tcputils import *
import time
Segment = namedtuple('Segment', ['msg','time','rtr'])

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        print(src_addr)
        print(dst_addr)
        print(calc_checksum(segment, src_addr, dst_addr))
        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)
        (dst_addr_res, dst_port_res, src_addr_res, src_port_res) = (src_addr, src_port, dst_addr, dst_port)
        if flags & FLAGS_SYN == FLAGS_SYN:
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no+1)
            conexao.seq_no = seq_no + 1
            conexao.ack_no = seq_no + 1
            # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
            # TODO: talvez você precise passar mais coisas para o construtor de conexão
            header =  make_header(src_port_res, dst_port_res, seq_no, seq_no+1, FLAGS_SYN | FLAGS_ACK)
            header = fix_checksum(header, src_addr_res, dst_addr_res)
            self.rede.enviar(header, dst_addr_res)
                    
            # TODO: você precisa fazer o handshake aceitando a conexão. Escolha se você acha melhor
            # fazer aqui mesmo ou dentro da classe Conexao.

            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao, seq_start):
        self.seq_start = seq_start
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.closed = False
        self.not_ack = []
        self.timer = None
        self.dev_rtt = None
        self.estimated_rtt = None
        self.timeout_interval = 1

    def _timer_callback(self):
        (_, _, dst_addr, _) = self.id_conexao
        self.servidor.rede.enviar(self.not_ack[0].msg, dst_addr)
        self.not_ack[0] = self.not_ack[0]._replace(rtr=True)
        self.timer = asyncio.get_event_loop().call_later(self.timeout_interval, self._timer_callback)

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        if self.closed:
            return 
        print('recebido payload: %r' % payload)
        if (seq_no > self.ack_no - 1 and ((flags & FLAGS_ACK) == FLAGS_ACK)):
            if (self.not_ack and not self.not_ack[0].rtr):
                rtt = time.time() - self.not_ack[0].time
                if (not self.dev_rtt or not self.estimated_rtt):
                    self.estimated_rtt = rtt
                    self.dev_rtt = rtt/2
                else:
                    self.estimated_rtt = (1-0.125)*self.estimated_rtt + 0.125*rtt
                    self.dev_rtt = (1 - 0.25)*self.dev_rtt + 0.25*abs(rtt-self.estimated_rtt)
                self.timeout_interval = self.estimated_rtt + 4*self.dev_rtt

            if (self.not_ack):
                self.not_ack.pop(0)
                if (self.timer):
                    self.timer.cancel()
                if (self.not_ack):
                    self.timer = asyncio.get_event_loop().call_later(self.timeout_interval, self._timer_callback)
                else:
                    self.timer.cancel()
        if (seq_no != self.ack_no):
            return
        if (flags & FLAGS_FIN == FLAGS_FIN):
            self.callback(self, b'')
        elif len(payload) == 0:
            return
            
        self.ack_no += max(1, len(payload))
        (src_addr, src_port, dst_addr, dst_port) = self.id_conexao
        header = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK)
        header = fix_checksum(header, src_addr, dst_addr)
        self.servidor.rede.enviar(header, dst_addr)
        self.callback(self, payload)

    # Os métodos abaixo fazem parte da API

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """
        if len(dados) <= MSS:
            (src_addr, src_port, dst_addr, dst_port) = self.id_conexao
            msg =  make_header(src_port, dst_port, self.seq_no, self.ack_no, FLAGS_ACK) + dados
            msg = fix_checksum(msg, src_addr,dst_addr)
            self.servidor.rede.enviar(msg, dst_addr)
            self.seq_no += len(dados)
            self.not_ack.append(Segment(msg,time.time(),False))
            self.timer = asyncio.get_event_loop().call_later(self.timeout_interval, self._timer_callback)
        else:
            self.enviar(dados[:MSS])
            self.enviar(dados[MSS:])

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        (src_addr, src_port, dst_addr, dst_port) = self.id_conexao
        header = make_header(src_port, dst_port, self.seq_no , self.ack_no, FLAGS_FIN) 
        header = fix_checksum(header, src_addr, dst_addr)  
        self.servidor.rede.enviar(header, dst_addr)     
        self.closed = True