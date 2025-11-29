import asyncio
import websockets
import logging

async def test_websocket():
    uri = "ws://localhost:8000/ws/logs/test_task"
    try:
        async with websockets.connect(uri) as websocket:
            print("Successfully connected to WebSocket!")
            # Send a test message if needed, or just close
            await websocket.close()
            print("Connection closed.")
    except Exception as e:
        print(f"Failed to connect: {e}")

if __name__ == "__main__":
    asyncio.run(test_websocket())
