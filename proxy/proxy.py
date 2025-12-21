"""
TCP Proxy for MITM Detection System
Intercepts and manipulates traffic between client and server to simulate MITM attacks.
"""

import socket
import threading
import logging
import os
import time
from enum import Enum


class AttackMode(Enum):
    # Simulation des modes MITM
    TRANSPARENT = "transparent" # Redirige le trafic vers le serveur réel
    MODIFY = "modify" # Modifie le trafic avant de le transmettre
    REPLAY = "replay" # Répète le dernier message reçu
    DELAY = "delay" # Retarde le trafic avant de le transmettre


class MITMProxy:
    # Proxy serveur

    def __init__(self, proxy_host, proxy_port, server_host, server_port, mode, delay_seconds,buffer_size=4096):
        #Initialisation des attributs
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.server_host = server_host
        self.server_port = server_port
        self.buffer_size = buffer_size
        self.delay_seconds = delay_seconds
        
        try:
            self.mode = AttackMode(mode.lower()) # .lower() pour normaliser le mode
        except ValueError:
            self.mode = AttackMode.TRANSPARENT # Si le mode est invalide, on utilise le mode transparent par defaut
            logging.warning(f"Invalid mode '{mode}', defaulting to transparent")
        
        self.last_message = None # Stockage du dernier message reçu
        self.proxy_socket = None # Socket du proxy
        self._setup_logging() # Configuration du logging

    def _setup_logging(self):
        # Configuration du logging pour le proxy
        logging.basicConfig(
            level=logging.INFO, # Niveau de logging
            format="%(asctime)s - [PROXY] - %(levelname)s - %(message)s" # Format Préférée
        )
        self.logger = logging.getLogger(__name__)

    def _process_data(self, data):
        # Traitement des données selon le mode
        if self.mode == AttackMode.TRANSPARENT:
            return data

        elif self.mode == AttackMode.MODIFY:
            modified = data.replace(b"HELLO", "BONJOUR Manipulé".encode("utf-8")) # Manipulation des données
            self.logger.warning("MODE = Modify → message altered") # Logging de la manipulation
            return modified

        elif self.mode == AttackMode.REPLAY:
            if self.last_message is not None:
                self.logger.warning("MODE = Replay → replaying old message") # Logging de la répétition
                return self.last_message
            self.last_message = data
            return data

        elif self.mode == AttackMode.DELAY:
            self.logger.warning(f"MODE = Delay → delaying {self.delay_seconds}s") # Logging de la retarde
            time.sleep(self.delay_seconds)
            return data

        return data

    def _forward(self, source, destination, direction):
        """Forward data from source to destination with optional manipulation."""
        try:
            while True:
                data = source.recv(self.buffer_size)
                if not data:
                    break

                # Stockage du dernier message pour la simulation de l'attaque de répétition
                self.last_message = data
                
                # Traitement des données selon le mode
                processed = self._process_data(data)
                destination.sendall(processed)

                self.logger.info(f"{direction}: forwarded {len(processed)} bytes") # Logging de la transmission

        except Exception as e:
            self.logger.info(f"{direction}: stopped ({e})") # Logging de la fin de la transmission

        finally:
            source.close()
            destination.close()

    def _handle_connection(self, client_socket, client_addr):
        """Gestion d'une connexion client en établissant une connexion serveur et en transmettant les données."""
        self.logger.info(f"Client connected from {client_addr}") # Logging de la connexion

        try:
            # Connexion au serveur réel
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((self.server_host, self.server_port))
            self.logger.info(f"Connected to server at {self.server_host}:{self.server_port}")

            # Création des threads de transmission bidirectionnelle
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

            # Start forwarding
            client_to_server.start()
            server_to_client.start()

            # Wait for both threads to complete
            client_to_server.join()
            server_to_client.join()

        except Exception as e:
            self.logger.error(f"Error handling connection: {e}")
            client_socket.close()

    def run(self):
        """Démarrage du serveur proxy et écoute des connexions."""
        try:
            # Création et configuration du socket du proxy
            self.proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Création d'un socket
            self.proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Configuration du socket
            self.proxy_socket.bind((self.proxy_host, self.proxy_port)) # Connexion au proxy
            self.proxy_socket.listen(1) # écoute des connexions
            self.logger.info(f"Proxy listening on {self.proxy_host}:{self.proxy_port}") # Logging de la connexion
            self.logger.info(f"Running in MODE={self.mode.value}") # Logging du mode

            # Gestion de la connexion client
            client_socket, client_addr = self.proxy_socket.accept()
            self._handle_connection(client_socket, client_addr)

        except KeyboardInterrupt: # Gérer l'interruption via Ctrl+C
            self.logger.info("Proxy interrupted (Ctrl+C)")

        except Exception as e: # Gérer les exceptions
            self.logger.exception(f"Proxy error: {e}")

        finally:
            self.close()

    def close(self):
        """Fermeture du socket du proxy."""
        if self.proxy_socket:
            self.proxy_socket.close()
            self.logger.info("Proxy closed")


def main():
    """Point d'entrée de l'application proxy."""
    
    # Lecture de la configuration des variables d'environnement
    proxy_host = os.getenv("PROXY_LISTEN_HOST", "0.0.0.0")
    proxy_port = int(os.getenv("PROXY_LISTEN_PORT", "9000"))
    server_host = os.getenv("PROXY_SERVER_HOST", "server")
    server_port = int(os.getenv("PROXY_SERVER_PORT", "9001"))
    mode = os.getenv("PROXY_MODE", "transparent")
    delay_seconds = int(os.getenv("PROXY_DELAY_SECONDS", "3"))
    buffer_size = int(os.getenv("PROXY_BUFFER_SIZE", "4096"))

    # Création et lancement du proxy
    proxy = MITMProxy(
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        server_host=server_host,
        server_port=server_port,
        mode=mode,
        delay_seconds=delay_seconds,
        buffer_size=buffer_size
    )
    proxy.run()


if __name__ == "__main__":
    main()
