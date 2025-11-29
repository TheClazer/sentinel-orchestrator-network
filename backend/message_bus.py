import logging
import json
from typing import Dict, List, Any
from fastapi import WebSocket, WebSocketDisconnect
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MessageBus:
    def __init__(self):
        # Registry mapping Agent DIDs (strings) to Ed25519 Public Keys (hex strings)
        self.registry: Dict[str, str] = {}
        # Active WebSocket connections
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("New WebSocket connection established")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info("WebSocket connection closed")

    def register_agent(self, did: str, public_key_hex: str):
        """Registers an agent with its DID and public key."""
        self.registry[did] = public_key_hex
        logger.info(f"Registered agent {did} with public key {public_key_hex[:10]}...")

    async def publish(self, envelope: Dict[str, Any]):
        """
        Verifies the signature of the envelope and broadcasts if valid.
        
        Expected envelope structure:
        {
            "sender_did": "did:...",
            "payload": { ... },
            "signature": "hex_string"
        }
        """
        sender_did = envelope.get("sender_did")
        payload = envelope.get("payload")
        signature_hex = envelope.get("signature")

        if not sender_did or not payload or not signature_hex:
            logger.warning("Dropped message: Missing required envelope fields")
            return

        if sender_did not in self.registry:
            logger.warning(f"Dropped message: Unknown sender DID {sender_did}")
            return

        public_key_hex = self.registry[sender_did]

        try:
            # Verify the signature
            verify_key = VerifyKey(bytes.fromhex(public_key_hex))
            
            # Serialize payload to bytes for verification
            # Ensure consistent serialization (e.g., no spaces, sorted keys)
            message_bytes = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
            
            verify_key.verify(message_bytes, bytes.fromhex(signature_hex))
            
            # If verification succeeds, broadcast the message
            logger.info(f"Verified message from {sender_did}. Broadcasting...")
            await self.broadcast(envelope)

        except BadSignatureError:
            logger.error(f"SECURITY ALERT: Invalid signature from {sender_did}. Dropping message.")
        except Exception as e:
            logger.error(f"Error processing message: {str(e)}")

    async def broadcast(self, message: Dict[str, Any]):
        """Broadcasts the message to all connected WebSockets."""
        disconnected_clients = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Failed to send to client: {e}")
                disconnected_clients.append(connection)
        
        for connection in disconnected_clients:
            self.disconnect(connection)

    async def subscribe(self, websocket: WebSocket):
        """Endpoint for Frontend to listen to events."""
        await self.connect(websocket)
        try:
            while True:
                # Keep the connection open. 
                # We can also handle incoming messages from frontend if needed, 
                # but for now we just wait for disconnection.
                await websocket.receive_text()
        except WebSocketDisconnect:
            self.disconnect(websocket)
