"""
Client TCP
"""

import socket # Socket pour la communication réseau
import logging # Logging pour le débogage
import time # Time pour les timestamps
import os # OS pour les opérations système


class MessageClient:
    """Client qui envoie des messages structurés au serveur"""
    def __init__(self, host, port, message_interval, payload):

        #Initialisation des attributs
        self.host = host
        self.port = port
        self.message_interval = message_interval
        self.payload = payload
        self.socket = None
        self.sequence_number = 1 # Numéro de séquence de départ
        self._setup_logging()

    def _setup_logging(self):
        # Configuration du logging pour le client
        logging.basicConfig(
            level=logging.INFO, # Niveau de logging
            format="%(asctime)s - [CLIENT] - %(levelname)s - %(message)s" # Format Préférée
        )
        self.logger = logging.getLogger(__name__)

    def _create_message(self):
        # Création d'un message structuré avec le numéro de séquence et le timestamp
        timestamp = int(time.time()) # Timestamp actuel
        message = f"SEQ={self.sequence_number}|TS={timestamp}|DATA={self.payload}\n" # Message structuré
        return message

    def connect(self):
        # Établissement de la connexion au proxy
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Création d'un socket
        self.socket.connect((self.host, self.port)) # Connexion au proxy
        self.logger.info(f"Connected to proxy at {self.host}:{self.port}") # Logging de la connexion

    def send_message(self):
        # Envoi d'un message au proxy
        message = self._create_message() # Création d'un message
        self.socket.sendall(message.encode("utf-8")) # Envoi du message
        self.logger.info(f"Sent: {message.strip()}") # Logging du message envoyé
        self.sequence_number += 1 # Incrémentation du numéro de séquence

    def run(self):
        # Boucle principale du client
        try:
            self.connect() # Établissement de la connexion au proxy
            while True:
                self.send_message() # Envoi d'un message au proxy
                time.sleep(self.message_interval) # Intervalle entre les messages

        except KeyboardInterrupt: # Gérer l'interruption via Ctrl+C
            self.logger.info("Client interrupted (Ctrl+C)")

        except ConnectionRefusedError: # Gérer la refus de connexion
            self.logger.error(f"Connection refused to {self.host}:{self.port}")

        except Exception as e: # Gérer les exceptions
            self.logger.exception(f"Client error: {e}")

        finally:
            self.close() # Fermer la connexion

    def close(self):
        # Fermeture de la connexion
        if self.socket:
            self.socket.close()
            self.logger.info("Client closed")


def main():
    # Point d'entrée de l'application client

    # Lecture de la configuration des variables d'environnement
    host = os.getenv("CLIENT_PROXY_HOST", "proxy") # Hôte du proxy
    port = int(os.getenv("CLIENT_PROXY_PORT", "9000")) # Port du proxy
    interval = float(os.getenv("CLIENT_MESSAGE_INTERVAL", "1.0")) # Intervalle entre les messages
    payload = os.getenv("CLIENT_MESSAGE_PAYLOAD", "HELLO") # Payload des messages

    # Création et lancement du client
    client = MessageClient(
        host=host, 
        port=port,
        message_interval=interval,
        payload=payload
    )
    client.run()


if __name__ == "__main__":
    main()
