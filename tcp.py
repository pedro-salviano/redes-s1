import asyncio
import math
import time
from tcputils import *
import random

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

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
            # TODO: talvez você precise passar mais coisas para o construtor de conexão
            ack_no = seq_no+1
            seq_no = random.randint(0, 0xffff)

            flags += FLAGS_ACK
            self.rede.enviar(fix_checksum(make_header(dst_port, src_port, seq_no, ack_no, flags),dst_addr,src_addr),src_addr)

            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, ack_no, seq_no+1)

            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao, ack_no, seq_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.timer = None

        self.janela = 1
        self.closing = False
        self.timeoutHapenned = False
        self.retransmitting = False

        self.lastAckRcv = seq_no
        self.qtdBytesAcked = 0
        self.pending = b''

        self.unsent = b''
        self.mensagem_anterior = None
        self.ack_no = ack_no
        self.seq_no = seq_no
        self.timeout_interval = 0.5

        self.sample_rtt = None
        self.estimated_rtt = None
        self.dev_rtt = None
        self.begin_time = None
        self.end_time = None
        self.primeiro = True


    def _start_timer(self):
        if self.timer:
            self._stop_timer()
        print("start timer")
        self.timer = asyncio.get_event_loop().call_later(self.timeout_interval, self.timeout)
        print(f"janela {self.janela}")
        print(f"timeout interval {self.timeout_interval}")

    def _stop_timer(self):
        #print("stop timer")
        self.timer.cancel()
        self.timer = None

    def timeout(self):
        print("timeout")
        self.timer = None
        self.janela = max(self.janela // 2 , 1)
        self.timeoutHapenned = True
        print(f"O window size atual é {self.janela} MSS.")
        self.retransmit()
        self._start_timer()

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        print("rdt rcv")
        if self.ack_no != seq_no:
            return

        src_addr = self.id_conexao[0]
        src_port = self.id_conexao[1]
        dest_addr = self.id_conexao[2]
        dest_port = self.id_conexao[3]

        if(flags & FLAGS_FIN) == FLAGS_FIN and not self.closing:
            self.fecharConexao()

        if (flags & FLAGS_ACK) == FLAGS_ACK:
            if self.closing:
                del self.servidor.conexoes[self.id_conexao]
                return

            if ack_no > self.lastAckRcv:
                self.qtdBytesAcked = ack_no - self.lastAckRcv
                
                self.pending = self.pending[ self.qtdBytesAcked: ]
                self.lastAckRcv = ack_no

                print(self.retransmitting)
                if self.pending:
                    self._start_timer()
                else:
                    if self.timer:
                        self._stop_timer()
                    
                    if not self.retransmitting:
                        self.calcRTT()
                    else:
                        self.retransmitting = False

        if self.qtdBytesAcked >= MSS:
            self.qtdBytesAcked -= MSS
            self.janela +=1

            self.enviarPendente()

        if(payload):

            dados = payload

            self.callback(self, dados)

            self.mensagem_anterior = payload

            #print("self.ack_no: %r + len(payload): %r = %r" %(self.ack_no, len(payload), self.ack_no+len(payload)))
            self.ack_no += len(payload)

            self.servidor.rede.enviar(fix_checksum(make_header(dest_port, src_port, self.seq_no, self.ack_no, flags), dest_addr, src_addr), dest_addr)
            if not self.timer:
                self._start_timer()

    def enviarParaAPP(self, dados):
        print("enviar para app")
        if self.retransmitting:
            seq_no = self.lastAckRcv
        else:
            self.begin_time = time.time()
            seq_no = self.seq_no
            self.pending += dados
            self.seq_no += len(dados)

        segment = fix_checksum(make_header(self.id_conexao[1], self.id_conexao[3], seq_no, self.ack_no, FLAGS_ACK)+dados, self.id_conexao[0], self.id_conexao[2])

        self.servidor.rede.enviar(segment, self.id_conexao[2])

        if not self.timer and not self.closing:
            self._start_timer()

    def enviarPendente(self):
        print("enviarPendente")
        tamanhoPendente = (self.janela * MSS) - len(self.pending)

        if (tamanhoPendente >0):
            packet = self.unsent[ :tamanhoPendente]

            if(len(packet) == 0):
                return

            self.unsent = self.unsent[tamanhoPendente : ]

            qtdPackets = math.ceil(len(packet) / MSS)
            if qtdPackets == 0:
                qtdPackets = 1
            for i in range(qtdPackets):
                segment = packet[i * MSS : (i+1) * MSS]
                self.enviarParaAPP(segment)

    def retransmit(self):
        print("retransmit")
        self.retransmitting = True
        payload = self.pending[ : (min(MSS, len(self.pending)))]
        self.enviarParaAPP(payload)

    def calcRTT(self):
        print("\n"+"calcRTT"+"\n")
        self.end_time = time.time()

        alfa = 0.125
        beta = 0.25


        self.sample_rtt = self.end_time - self.begin_time

        if self.primeiro:
            self.primeiro = False

            self.estimated_rtt = self.sample_rtt
            self.dev_rtt = self.sample_rtt / 2
        else:
            self.estimated_rtt = ((1 - alfa)* self.estimated_rtt) + (alfa * self.sample_rtt)

            self.dev_rtt = ((1- beta)* self.dev_rtt) + (beta*abs(self.sample_rtt - self.estimated_rtt))

        self.timeout_interval = self.estimated_rtt + (4*self.dev_rtt)

    def fecharConexao(self):
        print("fecha conexao")
        self.closing = True

        self.callback(self, b"")
        self.ack_no += 1

        self.enviarParaAPP(b"")

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
        # TODO: implemente aqui o envio de dados.
        # Chame self.servidor.rede.enviar(segmento, dest_addr) para enviar o segmento
        # que você construir para a camada de rede.
        
        self.unsent += dados
        packet = self.unsent[ :self.janela*MSS]
        self.unsent = self.unsent[self.janela*MSS: ]


        qtdPackets = math.ceil(len(packet) / MSS)
        if qtdPackets == 0:
            qtdPackets = 1
        for i in range(qtdPackets):
            segment = packet[i * MSS : (i+1) * MSS]
            self.enviarParaAPP(segment)

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """

        self.servidor.rede.enviar(fix_checksum(make_header(self.id_conexao[3], self.id_conexao[1], self.seq_no, self.ack_no, FLAGS_FIN), self.id_conexao[2], self.id_conexao[0]), self.id_conexao[0])
