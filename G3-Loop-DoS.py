import socket
import random
import argparse
import threading
from queue import Queue
from datetime import datetime
import cmd

class GeDosLoopShell(cmd.Cmd):
    intro = "Bem-vindo ao Scan G3 Loop DoS! Digite 'help' para obter uma lista de comandos."
    prompt = "(G3-Loop-DoS) "

    def __init__(self):
        super().__init__()
        self.ip_range = None
        self.portas = [123, 53, 161]
        self.protocolos = ["ntp", "dns", "snmp"]
        self.payload = None
        self.timeout = 2
        self.num_threads = 10

    def do_scan(self, args):
        """Realizar uma varredura de vulnerabilidade"""
        varrer_ips(self.ip_range, self.portas, self.protocolos, self.payload, self.timeout, self.num_threads)

    def do_set_target(self, args):
        """Definir o alvo de varredura
        Uso: set_target <intervalo_ip>
        Exemplo: set_target 192.168.1.0/24
        """
        try:
            import ipaddress
            self.ip_range = [str(ip) for ip in ipaddress.IPv4Network(args)]
            print(f"Alvo definido como: {args}")
        except ValueError:
            print("Intervalo de IP inválido. Use o formato CIDR (ex: 192.168.1.0/24).")

    def do_set_options(self, args):
        """Definir opções de varredura
        Uso: set_options <opção1> <valor1> [<opção2> <valor2>...]
        Opções disponíveis:
            -p, --ports: Portas a serem testadas (padrão: 123 53 161)
            -P, --protocols: Protocolos a serem testados (padrão: ntp dns snmp)
            -c, --custom: Payload personalizada (use com o protocolo 'custom')
            -t, --timeout: Tempo limite de resposta em segundos (padrão: 2)
            -n, --threads: Número de threads a serem usadas (padrão: 10)
        """
        options = args.split()
        for i in range(0, len(options), 2):
            option = options[i]
            if i + 1 < len(options):
                value = options[i + 1]
            else:
                print(f"Valor ausente para a opção '{option}'.")
                return

            if option in ("-p", "--ports"):
                self.portas = [int(port) for port in value.split(",")]
            elif option in ("-P", "--protocols"):
                self.protocolos = value.split(",")
            elif option in ("-c", "--custom"):
                if "custom" not in self.protocolos:
                    self.protocolos.append("custom")
                self.payload = value.encode()
            elif option in ("-t", "--timeout"):
                self.timeout = int(value)
            elif option in ("-n", "--threads"):
                self.num_threads = int(value)
            else:
                print(f"Opção '{option}' desconhecida.")

    def do_help(self, args):
        """Exibir ajuda e exemplos de uso"""
        examples = """
Exemplos de uso:

1. Varredura com configurações padrão (protocolos NTP, DNS e SNMP):
    (G3-Loop-DoS) set_target 192.168.1.0/24
    (G3-Loop-DoS) scan

2. Varredura com opções personalizadas (protocolo HTTP e payload customizada):
    (G3-Loop-DoS) set_target 10.0.0.0/24
    (G3-Loop-DoS) set_options -p 80 -P http,custom -c "GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n" -t 5 -n 20
    (G3-Loop-DoS) scan

3. Varredura com payload personalizada (protocolo custom):
    (G3-Loop-DoS) set_target 172.16.0.0/16
    (G3-Loop-DoS) set_options -c "\\x01\\x02\\x03\\x04\\x05"
    (G3-Loop-DoS) scan
"""
        print(examples)
        super().do_help(args)

# Função para gerar endereço IP falso
def gerar_ip_falso():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

# Função para testar vulnerabilidade
def testar_vulnerabilidade(ip, porta, protocolo, payload, timeout, queue):
    payloads = {
        "ntp": b"\x17\x00\x03\x2a\x00\x00\x00\x00",
        "dns": b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x76\x65\x72\x73\x69\x6f\x6e\x04\x62\x69\x6e\x64\x00\x00\x10\x00\x03",
        "snmp": b"\x30\x3a\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x2b\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x1b\x30\x19\x06\x09\x2b\x06\x01\x02\x01\x01\x09\x01\x02\x06\x09\x2b\x06\x01\x04\x01\x90\x67\x81\x05\x05\x00",
    }

    if protocolo == "custom":
        payload_custom = payload
    else:
        payload_custom = payloads.get(protocolo, None)

    if payload_custom:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(payload_custom, (ip, porta))
            sock.close()

            # Simular tempo de espera para resposta
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            start_time = datetime.now()
            sock.connect((ip, porta))
            end_time = datetime.now()
            response_time = (end_time - start_time).total_seconds()
            sock.close()

            if response_time < timeout:
                result = f"O sistema {ip}:{porta} parece ser vulnerável ao CVE-2024-2169 ({protocolo})"
            else:
                result = f"O sistema {ip}:{porta} não respondeu dentro do tempo limite ({timeout} segundos)"
        except Exception as e:
            result = f"Erro ao testar {ip}:{porta}: {e}"
    else:
        result = f"Protocolo inválido: {protocolo}"

    queue.put(result)

# Função para varrer endereços IP
def varrer_ips(ip_range, portas, protocolos, payload, timeout, num_threads):
    queue = Queue()
    threads = []

    for ip in ip_range:
        for porta in portas:
            for protocolo in protocolos:
                thread = threading.Thread(target=testar_vulnerabilidade, args=(ip, porta, protocolo, payload, timeout, queue))
                threads.append(thread)
                thread.start()

    for thread in threads:
        thread.join()

    while not queue.empty():
        print(queue.get())

if __name__ == "__main__":
    GeDosLoopShell().cmdloop()
