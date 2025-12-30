"""
Serveur TCP
Reçoit les messages et détecte les attaques MITM
"""

import socket
import logging
import time
import os


class Message:
    """ Message structuré avec numéro de séquence, timestamp et payload."""
    def __init__(self, sequence, timestamp, payload):
        self.sequence = sequence
        self.timestamp = timestamp
        self.payload = payload


class DetectionServer:
    """ Serveur qui détecte les attaques MITM """
    def __init__(self, host, port, max_delay, buffer_size):
        
        # Initialisation des attributs  
        self.host = host 
        self.port = port
        self.max_delay = max_delay
        self.buffer_size = buffer_size
        
        self.expected_sequence = 1  # Numéro de séquence attendu
        self.server_socket = None
        self.client_socket = None
        self._setup_logging()

    def _setup_logging(self):
        """ Configuration du logging """
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - [SERVER] - %(levelname)s - %(message)s" #Format des Logs
        )
        self.logger = logging.getLogger(__name__)

    def _parse_message(self, raw_message):

        """ Décomposition du message en format structuré """
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

    def _detect_dropped_packets(self, sequence):
        """ Détection des paquets perdus """
        
        if sequence > self.expected_sequence:
            # Gap detected - packets were dropped
            missing_range = list(range(self.expected_sequence, sequence))
            self.logger.critical(
                f"[ALERT] DROPPED PACKETS DETECTED: Missing sequence numbers {missing_range}"
            )
            self.expected_sequence = sequence + 1
            return True
        elif sequence == self.expected_sequence:
            # Normal case - sequence is as expected
            self.expected_sequence = sequence + 1
            return False
        else:
            # sequence < expected_sequence - handled by reorder detection
            return False

    def _detect_reorder_attack(self, sequence):
        """ Détection des paquets reordonnés """
        if sequence < self.expected_sequence:
            self.logger.critical(
                f"[ALERT] OUT-OF-ORDER PACKET: Received SEQ={sequence}, Expected SEQ={self.expected_sequence}"
            )
            return True
        return False

    def _detect_delay_attack(self, timestamp):
        """Detect delay attacks"""
        current_time = int(time.time())
        delay = current_time - timestamp

        if delay > self.max_delay:
            self.logger.critical(
                f"[ALERT] DELAY ATTACK DETECTED: {delay}s > {self.max_delay}s"
            )
            return True
        
        return False

    def _detect_integrity_violation(self, raw_message):
        """ Détection des violations d'intégrité (Message qui ne respecte pas le format structuré attendu) """
        try:
            self._parse_message(raw_message)
            return False
        except Exception:
            self.logger.critical(
                f"[ALERT] Message integrity violation detected: {raw_message}"
            )
            return True

    def _process_message(self, raw_message):
        """ Algorithme de traitement et d'analyse des messages arrivés"""
        if self._detect_integrity_violation(raw_message):
            return
        try:
            message = self._parse_message(raw_message) 
            
            # Vérification si la détection est activée
            detection_enabled = os.getenv("SERVER_DETECTION_ENABLED", "true").lower() == "true"

            # Algorithme de détection (seulement si activé)
            if detection_enabled:
                # Vérification si le paquet est reordonné
                self._detect_reorder_attack(message.sequence)
                
                # Vérification si le paquet est perdu
                self._detect_dropped_packets(message.sequence)
                
                # Vérification si le paquet est retardé
                self._detect_delay_attack(message.timestamp)
            
            delay = int(time.time()) - message.timestamp

            # Log du message normal
            self.logger.info(
                f"SEQ={message.sequence} | TS={message.timestamp} | Delay={delay}s | DATA={message.payload}"
            )

        except Exception as e:
            self.logger.error(f"Error processing message: {e}")

    def _handle_client(self, client_socket, address):
        """ Gestion de la connexion et du traitement des messages """
        self.logger.info(f"Connected with {address}")

        try:
            while True:
                data = client_socket.recv(self.buffer_size)
                if not data:
                    self.logger.info("Client disconnected")
                    break

                # Décodage et séparation des messages
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
        """ Démarrage du serveur de détection et écoute des connexions """
        try:
            # Création et configuration du socket serveur
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(1)

            # Log server startup
            self.logger.info(f"Server started on {self.host}:{self.port}")
            self.logger.info(f"MAX_DELAY is set to {self.max_delay}s")
            self.logger.info("Waiting for connection...")

            # Accept client connection
            self.client_socket, address = self.server_socket.accept()
            self._handle_client(self.client_socket, address)

        except KeyboardInterrupt:
            self.logger.info("Server interrupted (Ctrl+C)")

        except Exception as e:
            self.logger.exception(f"Server error: {e}")

        finally:
            self.close()

    def close(self):
        # Fermeture des sockets et nettoyage des ressources
        if self.client_socket:
            self.client_socket.close()
        if self.server_socket:
            self.server_socket.close()
        self.logger.info("Server closed")


def main():
    """ Point d'entrée de l'application """
    
    # Lecture de la configuration des variables d'environnement
    host = os.getenv("SERVER_LISTEN_HOST")
    port = int(os.getenv("SERVER_LISTEN_PORT"))
    max_delay = float(os.getenv("SERVER_MAX_DELAY"))
    buffer_size = int(os.getenv("SERVER_BUFFER_SIZE"))

    # Création et démarrage du serveur
    server = DetectionServer(host=host, port=port, max_delay=max_delay, buffer_size=buffer_size)
    server.run()


if __name__ == "__main__":
    main()
