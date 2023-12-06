from fastapi import FastAPI
from routes.requirements import archive_router, verify_router, transaction_router
from routes.auth import auth_router

app = FastAPI()

app.include_router(auth_router)  
app.include_router(archive_router, prefix ="/archive")
app.include_router(verify_router, prefix ="/verify")
app.include_router(transaction_router, prefix ="/transaction")