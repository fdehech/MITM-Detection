"""
Proxy TCP pour le système de détection MITM
Intercepte et manipule le trafic entre le client et le serveur pour simuler des attaques MITM.
"""

import socket
import threading
import logging
import os
import time
import random
from enum import Enum
from collections import deque


class AttackMode(Enum):
    """MITM attack simulation modes"""
    TRANSPARENT = "transparent"  # Redirige le traffic sans alteration
    RANDOM_DELAY = "random_delay"  # Retarde les paquets par une durée aléatoire
    DROP = "drop"  # Retire aléatoirement des paquets
    REORDER = "reorder"  # Réorganise les paquets dans une fenêtre de tampon


class MITMProxy:
    """MITM Proxy Server"""

    def __init__(self, proxy_host, proxy_port, server_host, server_port, mode, 
                 delay_min=2.0, delay_max=10.0, drop_rate=0.3, reorder_window=5, buffer_size=4096):
        """Initialize proxy attributes"""
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.server_host = server_host
        self.server_port = server_port
        self.buffer_size = buffer_size
        
        # Mode d'attaque
        self.delay_min = delay_min
        self.delay_max = delay_max
        self.drop_rate = drop_rate
        self.reorder_window = reorder_window
        
        try:
            self.mode = AttackMode(mode.lower())
        except ValueError:
            self.mode = AttackMode.TRANSPARENT
            logging.warning(f"Invalid mode '{mode}', defaulting to transparent")
        
        self.proxy_socket = None
        self._setup_logging()

    def _setup_logging(self):
        """Configuration du logging pour le proxy"""
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - [PROXY] - %(levelname)s - %(message)s"
        )
        self.logger = logging.getLogger(__name__)

    def _process_data(self, data, buffer):
        """Traitement des données selon le mode d'attaque"""
        if self.mode == AttackMode.TRANSPARENT:
            return data

        elif self.mode == AttackMode.RANDOM_DELAY:
            delay = random.uniform(self.delay_min, self.delay_max)
            self.logger.warning(f"MODE = Random Delay → delaying {delay:.2f}s")
            time.sleep(delay)
            return data

        elif self.mode == AttackMode.DROP:
            # Retire aléatoirement des paquets selon drop_rate
            if random.random() < self.drop_rate:
                self.logger.warning(f"MODE = Drop → packet DROPPED (drop_rate={self.drop_rate})")
                return None  # Signal to drop this packet
            return data

        elif self.mode == AttackMode.REORDER:
            # Ajoute le paquet au tampon de reorganisation
            buffer.append(data)
            
            # Si le tampon est plein, sélectionne aléatoirement un paquet à envoyer
            if len(buffer) >= self.reorder_window:
                # Sélectionne aléatoirement un index à envoyer
                index = random.randint(0, len(buffer) - 1)
                packet = buffer[index]
                # Supprime par index (O(N) pour deque mais bon pour des fenêtres petites)
                del buffer[index]
                self.logger.warning(f"MODE = Reorder → sending packet from position {index} (buffer size: {len(buffer)})")
                return packet
            else:
                # Tampon non plein encore, garde le paquet
                self.logger.info(f"MODE = Reorder → buffering packet (buffer: {len(buffer)}/{self.reorder_window})")
                return None  # Signal to not send yet

        return data

    def _forward(self, source, destination, direction):
        """Forward data from source to destination with optional manipulation."""
        # Créer un tampon local pour cette direction si en mode de reorganisation
        buffer = deque(maxlen=self.reorder_window) if self.mode == AttackMode.REORDER else None
        
        try:
            while True:
                data = source.recv(self.buffer_size)
                if not data:
                    break
                
                # Traitement des données selon le mode d'attaque
                processed = self._process_data(data, buffer)
                
                # Si processed est None, le paquet est retiré ou tamponné
                if processed is not None:
                    destination.sendall(processed)
                    self.logger.info(f"{direction}: forwarded {len(processed)} bytes")

        except Exception as e:
            self.logger.info(f"{direction}: stopped ({e})")

        finally:
            # Vider le tampon de reorganisation si en mode de reorganisation
            if self.mode == AttackMode.REORDER and buffer and len(buffer) > 0:
                self.logger.info(f"[{direction}] Flushing reorder buffer ({len(buffer)} packets)")
                while buffer:
                    packet = buffer.popleft()
                    try:
                        destination.sendall(packet)
                    except:
                        pass
            
            try:
                source.close()
            except:
                pass
            try:
                destination.close()
            except:
                pass

    def _handle_connection(self, client_socket, client_addr):
        """Gestion de la connexion client en établissant une connexion serveur et en transférant les données."""
        self.logger.info(f"Client connected from {client_addr}")
        try:
            # Connexion au serveur réel
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((self.server_host, self.server_port))
            self.logger.info(f"Connected to server at {self.server_host}:{self.server_port}")

            # Créer des threads bidirectionnels
            client_to_server = threading.Thread(
                target=self._forward,
                args=(client_socket, server_socket, "CLIENT → SERVER"),
                daemon=True
            )
            server_to_client = threading.Thread(
                target=self._forward,
                args=(server_socket, client_socket, "SERVER → CLIENT"),
                daemon=True
            )

            # Démarre le transfert
            client_to_server.start()
            server_to_client.start()

            # Attend que les deux threads soient terminés
            client_to_server.join()
            server_to_client.join()

        except Exception as e:
            self.logger.error(f"Error handling connection from {client_addr}: {e}")
        finally:
            client_socket.close()

    def run(self):
        """Démarrer le serveur proxy et écouter les connexions."""
        try:
            # Créer et configurer le socket proxy
            self.proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.proxy_socket.bind((self.proxy_host, self.proxy_port))
            self.proxy_socket.listen(5)
            self.logger.info(f"Proxy listening on {self.proxy_host}:{self.proxy_port}")
            self.logger.info(f"Running in MODE={self.mode.value}")

            while True:
                # Gestion de la connexion client
                client_socket, client_addr = self.proxy_socket.accept()
                # Gestion de chaque connexion dans un nouveau thread pour supporter plusieurs clients
                client_thread = threading.Thread(
                    target=self._handle_connection,
                    args=(client_socket, client_addr),
                    daemon=True
                )
                client_thread.start()

        except KeyboardInterrupt:
            self.logger.info("Proxy interrupted (Ctrl+C)")

        except Exception as e:
            self.logger.exception(f"Proxy error: {e}")

        finally:
            self.close()


    def close(self):
        """Fermeture du socket proxy."""
        if self.proxy_socket:
            self.proxy_socket.close()
            self.logger.info("Proxy closed")


def main():
    """Point d'entrée de l'application."""
    
    # Lecture de la configuration des variables d'environnement
    proxy_host = os.getenv("PROXY_LISTEN_HOST")
    proxy_port = int(os.getenv("PROXY_LISTEN_PORT"))
    server_host = os.getenv("PROXY_SERVER_HOST")
    server_port = int(os.getenv("PROXY_SERVER_PORT"))
    mode = os.getenv("PROXY_MODE")
    
    # Paramètres de délai aléatoire
    delay_min = float(os.getenv("PROXY_DELAY_MIN"))
    delay_max = float(os.getenv("PROXY_DELAY_MAX"))
    
    # Paramètres de mode de perte
    drop_rate = float(os.getenv("PROXY_DROP_RATE"))
    
    # Paramètres de mode de reorganisation
    reorder_window = int(os.getenv("PROXY_REORDER_WINDOW"))
    
    buffer_size = int(os.getenv("PROXY_BUFFER_SIZE"))

    # Création et démarrage du proxy
    proxy = MITMProxy(
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        server_host=server_host,
        server_port=server_port,
        mode=mode,
        delay_min=delay_min,
        delay_max=delay_max,
        drop_rate=drop_rate,
        reorder_window=reorder_window,
        buffer_size=buffer_size
    )
    proxy.run()


if __name__ == "__main__":
    main()
