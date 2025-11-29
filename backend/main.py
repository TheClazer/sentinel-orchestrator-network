from fastapi import FastAPI, WebSocket, BackgroundTasks
from pydantic import BaseModel
from backend.message_bus import MessageBus
import uuid
import logging

# Initialize Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI
app = FastAPI()

# Initialize MessageBus
message_bus = MessageBus()

class ScanRequest(BaseModel):
    policy_id: str

async def mock_sentinel_agent(policy_id: str, task_id: str):
    """
    Mock Sentinel Agent logic.
    In a real scenario, this would perform the scan and publish results to the MessageBus.
    """
    logger.info(f"Sentinel Agent triggered for policy: {policy_id}, task_id: {task_id}")
    # Here we would normally publish messages to the bus
    # await message_bus.publish(...) 
    pass

@app.post("/api/v1/scan")
async def scan(request: ScanRequest, background_tasks: BackgroundTasks):
    task_id = str(uuid.uuid4())
    logger.info(f"Received scan request for policy_id: {request.policy_id}")
    
    # Trigger Sentinel agent (mock)
    background_tasks.add_task(mock_sentinel_agent, request.policy_id, task_id)
    
    return {"status": "scan_initiated", "task_id": task_id}

@app.websocket("/ws/logs/{task_id}")
async def websocket_endpoint(websocket: WebSocket, task_id: str):
    await message_bus.subscribe(websocket)
