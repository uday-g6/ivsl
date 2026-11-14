from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .database.db import Base, engine
from .api.devices import router as devices_router
from .api.scans import router as scans_router
from .api.device_engine import router as engine_router
from .api.filesystem import router as filesystem_router

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="IVSL - iOS Virtual Security Lab",
    description="Linux-based simulated iOS device research platform",
    version="0.2.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5174",
],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(devices_router)
app.include_router(engine_router)
app.include_router(filesystem_router)
app.include_router(scans_router)

@app.get("/")
def home():
    return {
        "name": "IVSL",
        "version": "0.2.0",
        "runtime": "Linux simulated environment",
        "modules": [
            "Device Manager",
            "iOS Version Profiles",
            "Virtual Filesystem",
            "Settings Engine"
        ],
        "status": "running"
    }

@app.get("/health")
def health():
    return {"status": "healthy"}
