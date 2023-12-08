from fastapi import FastAPI
from routes.requirements import archive_router, verify_router, transaction_router
from routes.auth import auth_router
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Setelan CORS untuk menerima permintaan dari semua domain
origins = ["*"]

# Tambahkan middleware CORS ke aplikasi
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)  
app.include_router(archive_router, prefix ="/archive")
app.include_router(verify_router, prefix ="/verify")
app.include_router(transaction_router, prefix ="/transaction")

