from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Optional
import json
from models.archive import ThreatData, ThreatLog
from models.users import UserJSON
from models.ticket import Tiket
from routes.auth import get_current_user
import httpx
import requests

# Load data from the JSON file
with open("data/archive.json", "r") as json_file:
    data = json.load(json_file)

# Assign the tables
threat_data = data.get("threat_data", [])
threat_log = data.get("threat_log", [])




archive_router = APIRouter(tags=['Archive'])
verify_router = APIRouter(tags=['Verify and Edit Archive'])
transaction_router = APIRouter(tags=['KAI Ticket Transaction Security Archive'])

#Archive Router
@archive_router.get("/threatdata", response_model = List[ThreatData])
async def retrieve_all_threatdata() -> List[ThreatData]:
    return threat_data

@archive_router.get("/threatdata/{threat_id}", response_model=ThreatData)
async def retrieve_threat_data(threat_id: int):
    threat_data = data.get("threat_data")
    for threat in threat_data:
        if threat["ThreatID"] == threat_id:
            return threat
    raise HTTPException(status_code=404, detail="ThreatData not found")

@archive_router.get("/threatlog/", response_model=List[ThreatLog])
def read_all_threatlog():
    return data.get("threat_log")

@archive_router.get("/threatlog/{log_id}", response_model=ThreatLog)
def read_threatlog(log_id: int):
    threat_log = data.get("threat_log")
    for log in threat_log:
        if log.get("LogID") == log_id:
            return log
    raise HTTPException(status_code=404, detail="ThreatLog not found")

#Verify and Edit Router
# PUT
@verify_router.put("/threatdata/{threat_id}", response_model=ThreatData)
def update_threatdata(threat_id: int, updated_threat: ThreatData, user: UserJSON = Depends(get_current_user)):
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to delete this requirement"
        )
    threat_data = data.get("threat_data")
    for i, threat in enumerate(threat_data):
        if threat.get("ThreatID") == threat_id:
            threat_data[i] = updated_threat.dict()
            with open("data/archive.json", "w") as write_file:
                json.dump(data, write_file, indent=4)
            return updated_threat
    raise HTTPException(status_code=404, detail="ThreatData not found")

@verify_router.put("/threatlog/{log_id}", response_model=ThreatLog)
def update_threatlog(log_id: int, updated_log: ThreatLog, user: UserJSON = Depends(get_current_user)):
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to delete this requirement"
        )
    threat_log = data.get("threat_log")
    for i, log in enumerate(threat_log):
        if log.get("LogID") == log_id:
            updated_log.LogID = log_id
            threat_log[i] = updated_log.dict()
            with open("data/archive.json", "w") as write_file:
                json.dump(data, write_file, indent=4)
            return updated_log
    raise HTTPException(status_code=404, detail="ThreatLog not found")


#POST
@verify_router.post("/threatdata", response_model=ThreatData)
def create_threatdata(threat: ThreatData, user: UserJSON = Depends(get_current_user)):
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to delete this requirement"
        )
    threat_data = data.get("threat_data")
    threat_id = max([t.get("ThreatID") for t in threat_data]) + 1
    threat.ThreatID = threat_id
    threat_data.append(threat.dict())
    with open("data/archive.json", "w") as write_file:
        json.dump(data, write_file, indent=4)
    return threat

@verify_router.post("/threatlog", response_model=ThreatLog)
def create_threatlog(log: ThreatLog, user: UserJSON = Depends(get_current_user)):
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to delete this requirement"
        )
    threat_log = data.get("threat_log")
    log_id = max([l.get("LogID") for l in threat_log]) + 1
    log.LogID = log_id
    threat_log.append(log.dict())
    with open("data/archive.json", "w") as write_file:
        json.dump(data, write_file, indent=4)
    return log

#DELETE

@verify_router.delete("/threatdata/{threat_id}", response_model=ThreatData)
def delete_threatdata(threat_id: int, user: UserJSON = Depends(get_current_user)):
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to delete this requirement"
        )
    threat_data = data.get("threat_data")
    for i, threat in enumerate(threat_data):
        if threat.get("ThreatID") == threat_id:
            deleted_threat = threat_data.pop(i)
            with open("data/archive.json", "w") as write_file:
                json.dump(data, write_file, indent=4)
            return deleted_threat
    raise HTTPException(status_code=404, detail="ThreatData not found")

@verify_router.delete("/threatlog/{log_id}", response_model=ThreatLog)
def delete_threatlog(log_id: int, user: UserJSON = Depends(get_current_user)):
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to delete this requirement"
        )
    
    threat_log = data.get("threat_log")
    for i, log in enumerate(threat_log):
        if log.get("LogID") == log_id:
            deleted_log = threat_log.pop(i)
            with open("data/archive.json", "w") as write_file:
                json.dump(data, write_file, indent=4)
            return deleted_log
    raise HTTPException(status_code=404, detail="ThreatLog not found")


#API dari Komeng
# Route untuk mendapatkan seluruh transaksi tiket
@transaction_router.get("/ticketing")
async def get_ticketing_data(user: UserJSON = Depends(get_current_user)):
    try:
        headers = {
            "Authorization" : f"Bearer {user.tokenTicket}"
        }
        # Lakukan permintaan HTTP ke API eksternal
        async with httpx.AsyncClient() as client:
            response = await client.get("https://holi-train-travel.grayrock-b84a6c08.australiaeast.azurecontainerapps.io/tiket", headers=headers)
        
        # Periksa apakah permintaan berhasil (kode status 200)
        response.raise_for_status()

        # Ubah respons JSON menjadi bentuk yang sesuai dengan model Anda
        ticketing_data = response.json()
        
        return ticketing_data

    except requests.RequestException as e:
        # Tangani kesalahan HTTP jika terjadi
        raise HTTPException(status_code=e.response.status_code, detail=str(e))

    except Exception as e:
        # Tangani kesalahan umum jika terjadi
        raise HTTPException(status_code=500, detail=str(e))
    
    
# Route untuk mengubah note
@transaction_router.put("/ticketing/{ticket_id}")
async def update_ticketing_data(ticket_id: int, newData: Tiket, user: UserJSON = Depends(get_current_user)):
    try:
        print(1)
        change_dict = newData.dict()
    except Exception as e:
        raise HTTPException(status_code=422, detail="Invalid input data")
    
    headers = {
        "Authorization" : f"Bearer {user.tokenTicket}"
    }
    
    url = f"https://holi-train-travel.grayrock-b84a6c08.australiaeast.azurecontainerapps.io/tiket/{ticket_id}"

    print(change_dict)
    
    try:
         # Lakukan permintaan HTTP ke API eksternal
        
        response =  requests.put(url, json=change_dict, headers=headers)
        
        # Periksa apakah permintaan berhasil (kode status 200)
        print(response.json())
        response.raise_for_status()
        # Ubah respons JSON menjadi bentuk yang sesuai dengan model Anda
        external_ticket_data = response.json()
        
        return external_ticket_data
    except httpx.HTTPError as e:
        # Tangani kesalahan HTTP jika terjadi
        raise HTTPException(status_code=400, detail=str(e))
    
    except Exception as e:
        # Tangani kesalahan umum jika terjadi
        raise HTTPException(status_code=500, detail=str(e))
    
        