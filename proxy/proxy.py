"""
TCP Proxy for MITM Detection System
Intercepts and manipulates traffic between client and server to simulate MITM attacks.
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
    TRANSPARENT = "transparent"  # Forward traffic without alteration
    RANDOM_DELAY = "random_delay"  # Delay packets by random duration
    DROP = "drop"  # Randomly drop packets
    REORDER = "reorder"  # Reorder packets within a buffer window


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
        
        # Attack mode parameters
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
        """Configure logging for the proxy"""
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - [PROXY] - %(levelname)s - %(message)s"
        )
        self.logger = logging.getLogger(__name__)

    def _process_data(self, data, buffer):
        """Process data according to the attack mode"""
        if self.mode == AttackMode.TRANSPARENT:
            return data

        elif self.mode == AttackMode.RANDOM_DELAY:
            delay = random.uniform(self.delay_min, self.delay_max)
            self.logger.warning(f"MODE = Random Delay → delaying {delay:.2f}s")
            time.sleep(delay)
            return data

        elif self.mode == AttackMode.DROP:
            # Randomly drop packets based on drop_rate
            if random.random() < self.drop_rate:
                self.logger.warning(f"MODE = Drop → packet DROPPED (drop_rate={self.drop_rate})")
                return None  # Signal to drop this packet
            return data

        elif self.mode == AttackMode.REORDER:
            # Add packet to reorder buffer
            buffer.append(data)
            
            # If buffer is full, randomly select a packet to send
            if len(buffer) >= self.reorder_window:
                # Randomly select an index to send
                index = random.randint(0, len(buffer) - 1)
                packet = buffer[index]
                # Remove by index (O(N) for deque but fine for small windows)
                del buffer[index]
                self.logger.warning(f"MODE = Reorder → sending packet from position {index} (buffer size: {len(buffer)})")
                return packet
            else:
                # Buffer not full yet, hold the packet
                self.logger.info(f"MODE = Reorder → buffering packet (buffer: {len(buffer)}/{self.reorder_window})")
                return None  # Signal to not send yet

        return data

    def _forward(self, source, destination, direction):
        """Forward data from source to destination with optional manipulation."""
        # Create a local buffer for this direction if in reorder mode
        buffer = deque(maxlen=self.reorder_window) if self.mode == AttackMode.REORDER else None
        
        try:
            while True:
                data = source.recv(self.buffer_size)
                if not data:
                    break
                
                # Process data according to attack mode
                processed = self._process_data(data, buffer)
                
                # If processed is None, packet is dropped or buffered
                if processed is not None:
                    destination.sendall(processed)
                    self.logger.info(f"{direction}: forwarded {len(processed)} bytes")

        except Exception as e:
            self.logger.info(f"{direction}: stopped ({e})")

        finally:
            # Flush reorder buffer if in reorder mode
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
        """Handle client connection by establishing server connection and forwarding data."""
        self.logger.info(f"Client connected from {client_addr}")

        try:
            # Connect to real server
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((self.server_host, self.server_port))
            self.logger.info(f"Connected to server at {self.server_host}:{self.server_port}")

            # Create bidirectional forwarding threads
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
            self.logger.error(f"Error handling connection from {client_addr}: {e}")
        finally:
            client_socket.close()

    def run(self):
        """Start proxy server and listen for connections."""
        try:
            # Create and configure proxy socket
            self.proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.proxy_socket.bind((self.proxy_host, self.proxy_port))
            self.proxy_socket.listen(5)
            self.logger.info(f"Proxy listening on {self.proxy_host}:{self.proxy_port}")
            self.logger.info(f"Running in MODE={self.mode.value}")

            while True:
                # Handle client connection
                client_socket, client_addr = self.proxy_socket.accept()
                # Handle each connection in a new thread to support multiple clients
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
        """Close proxy socket."""
        if self.proxy_socket:
            self.proxy_socket.close()
            self.logger.info("Proxy closed")


def main():
    """Application entry point."""
    
    # Read configuration from environment variables
    proxy_host = os.getenv("PROXY_LISTEN_HOST", "0.0.0.0")
    proxy_port = int(os.getenv("PROXY_LISTEN_PORT", "9000"))
    server_host = os.getenv("PROXY_SERVER_HOST", "server")
    server_port = int(os.getenv("PROXY_SERVER_PORT", "9001"))
    mode = os.getenv("PROXY_MODE", "transparent")
    
    # Random delay parameters
    delay_min = float(os.getenv("PROXY_DELAY_MIN", "2.0"))
    delay_max = float(os.getenv("PROXY_DELAY_MAX", "10.0"))
    
    # Drop mode parameters
    drop_rate = float(os.getenv("PROXY_DROP_RATE", "0.3"))
    
    # Reorder mode parameters
    reorder_window = int(os.getenv("PROXY_REORDER_WINDOW", "5"))
    
    buffer_size = int(os.getenv("PROXY_BUFFER_SIZE", "4096"))

    # Create and run proxy
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
