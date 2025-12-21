"""
Serveur TCP
Recoit les messages et detecte des attaques MITM potential
"""

import socket # Socket pour la communication reseau
import logging # Logging pour le debug
import time # Time pour les timestamps
import os # OS pour les operations system


class Message:
    """Message Structuré avec la numéro de sequence, le timestamp et le payload."""
    def __init__(self, sequence, timestamp, payload):
        self.sequence = sequence
        self.timestamp = timestamp
        self.payload = payload


class DetectionServer:
    """Serveur qui detecte les attaques MITM"""
    def __init__(self, host, port, max_delay, buffer_size):
        
        #Initialisation des attributs
        self.host = host 
        self.port = port
        self.max_delay = max_delay
        self.buffer_size = buffer_size
        
        self.last_sequence = 0
        self.server_socket = None
        self.client_socket = None
        self._setup_logging()

    def _setup_logging(self):
        #Configuration du logging pour le serveur

        logging.basicConfig(
            level=logging.INFO, #Niveau de logging
            format="%(asctime)s - [SERVER] - %(levelname)s - %(message)s" #Format Préférée
        )
        self.logger = logging.getLogger(__name__)

    def _parse_message(self, raw_message):
        # Décomposition du message
        parts = raw_message.split("|")
        fields = {}

        for part in parts:
            key, value = part.split("=", 1)
            fields[key] = value

        return Message(
            sequence=int(fields["SEQ"]),
            timestamp=int(fields["TS"]),
            payload=fields["DATA"]
        )

    def _detect_replay_attack(self, sequence):
        #Détection des attaques de replay ou de reordering
        if sequence <= self.last_sequence: #Si le numéro de séquence est inférieur ou égal au dernier numéro de séquence
            self.logger.critical(
                f"[ALERT] Replay or reordering detected (SEQ={sequence}, last={self.last_sequence})"
            )
            return True
        
        self.last_sequence = sequence
        return False

    def _detect_delay_attack(self, timestamp):
        #Détection des attaques de delay
        current_time = int(time.time()) #Timestamp actuel
        delay = current_time - timestamp #Différence entre le timestamp actuel et le timestamp du message

        if delay > self.max_delay: #Si la différence est supérieure au délai maximum
            self.logger.critical(
                f"[ALERT] Suspicious delay detected ({delay}s > {self.max_delay}s)"
            )
            return True
        
        return False

    def _detect_integrity_violation(self, raw_message):

        #Detection des violations d'intégrité
        try:
            self._parse_message(raw_message)
            return False
        except Exception:
            self.logger.critical(
                f"[ALERT] Message integrity violation detected: {raw_message}"
            )
            return True

    def _process_message(self, raw_message):

        #Analyse du message
        if self._detect_integrity_violation(raw_message):
            return

        try:
            message = self._parse_message(raw_message) 

            # Algorithme de detection
            delay = int(time.time()) - message.timestamp
            self._detect_replay_attack(message.sequence)
            self._detect_delay_attack(message.timestamp)

            # Log normal message
            self.logger.info(
                f"SEQ={message.sequence} | TS={message.timestamp} | Delay={delay}s | DATA={message.payload}"
            )

        except Exception as e:
            self.logger.error(f"Error processing message: {e}")

    def _handle_client(self, client_socket, address):

        """Gérer la connexion client et le traitement des messages."""
        self.logger.info(f"Connected with {address}")

        try:
            while True:
                data = client_socket.recv(self.buffer_size)
                if not data:
                    self.logger.info("Client disconnected")
                    break

                # Décodage et division par ligne pour traiter chaque message individuellement
                raw_data = data.decode("utf-8", errors="replace")
                messages = raw_data.strip().split("\n")
                
                for msg in messages:
                    if msg.strip():
                        self._process_message(msg.strip())

        except Exception as e:
            self.logger.error(f"Error handling client: {e}")

        finally:
            client_socket.close()

    def run(self):
        """Démarrage du serveur de detection et ecoute des connexions."""
        try:
            # Création et configuration du socket serveur
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(1)

            # Logging du démarrage du serveur
            self.logger.info(f"Server started on {self.host}:{self.port}")
            self.logger.info(f"MAX_DELAY is set to {self.max_delay}s")
            self.logger.info("Waiting for connection...")

            # Acceptation de la connexion client
            self.client_socket, address = self.server_socket.accept()
            self._handle_client(self.client_socket, address)

        except KeyboardInterrupt: # Gérer l'interruption via Ctrl+C
            self.logger.info("Server interrupted (Ctrl+C)")

        except Exception as e: # Gérer les exceptions
            self.logger.exception(f"Server error: {e}")

        finally:
            self.close()

    def close(self):
        """Fermeture de tous les sockets et nettoyage des ressources."""
        if self.client_socket:
            self.client_socket.close()
        if self.server_socket:
            self.server_socket.close()
        self.logger.info("Server closed")


def main():
    """Point d'entrée de l'application serveur."""
    
    # Lecture de la configuration des variables d'environnement
    host = os.getenv("SERVER_LISTEN_HOST", "0.0.0.0")
    port = int(os.getenv("SERVER_LISTEN_PORT", "9001"))
    max_delay = int(os.getenv("SERVER_MAX_DELAY", "2"))
    buffer_size = int(os.getenv("SERVER_BUFFER_SIZE", "4096"))

    # Création et lancement du serveur
    server = DetectionServer(host=host, port=port, max_delay=max_delay, buffer_size=buffer_size)
    server.run()


if __name__ == "__main__":
    main()
