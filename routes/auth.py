from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.hash import bcrypt
import jwt
import json
from models.users import Token, UserIn, UserJSON
import httpx
import requests

# Load user data from JSON file
with open("data/users.json", "r") as json_file:
    users_data = json.load(json_file)

auth_router = APIRouter(tags=["Authentication"])
JWT_SECRET = 'myjwtsecret'
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')


# Function to write user data to JSON file
def write_users_to_json():
    with open("data/users.json", "w") as json_file:
        json.dump(users_data, json_file, indent=4)

# Function to authenticate and get user
def authenticate_user(username: str, password: str):
    for user in users_data:
        if user['username'] == username and bcrypt.verify(password, user['password_hash']):
            print(user)
            return user
    return None

# OAuth2 password bearer for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')


# # Route to generate token lama
# @auth_router.post('/token', response_model=Token)
# async def generate_token(form_data: OAuth2PasswordRequestForm = Depends()):
#     user = authenticate_user(form_data.username, form_data.password)

#     if not user:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED, 
#             detail='Invalid username or password'
#         )

#     token_data = {"sub": user['username'], "id": user['id']}
#     token = jwt.encode(token_data, JWT_SECRET)

#     return {'access_token': token, 'token_type': 'bearer'}


# Route to generate token baru
@auth_router.post('/token', response_model=Token)
async def generate_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail='Invalid username or password'
        )

    token_data = {"sub": user['username'], "id": user['id']}
    token = jwt.encode(token_data, JWT_SECRET)

    friend_service_url = "https://holi-train-travel.grayrock-b84a6c08.australiaeast.azurecontainerapps.io/login"

    friend_token_data = {
        "username": form_data.username,
        "password": form_data.password
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(friend_service_url, data=friend_token_data)
        
        response.raise_for_status()
        friend_response_data = response.json()
        friend_token = friend_response_data.get("access_token")
        # menambahkan token ke user
        for user in users_data:
            if user['username'] == form_data.username :
                user['tokenTicket'] = friend_token
                write_users_to_json()

    except httpx.HTTPError as e:
        
        raise HTTPException(status_code=500, detail=f"Failed to generate token in friend's service: {str(e)}")
        
    return {'access_token': token, 'token_type': 'bearer', 'username' : form_data.username, 'tokenTicket': friend_token}






# Dependency to get current user
async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user_id = payload.get('id')
        user = next((u for u in users_data if u['id'] == user_id), None)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail='Invalid user'
            )
        return UserJSON(**user)  # Convert user dictionary to User Pydantic model
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail='Invalid token'
        )

# Route to get current user
@auth_router.get('/users/me', response_model=UserJSON)
async def get_user(user: UserJSON = Depends(get_current_user)):
    return user

# # Route to register a new user lama
# @auth_router.post('/register', response_model=UserJSON)
# async def register_user(user: UserIn):
#     user_id = len(users_data) + 1
#     password_hash = bcrypt.hash(user.password)
    
#     is_admin = False
#     if user.username == "pak bas" or "auva":
#         is_admin = True
        
#     new_user = {"id": user_id, "username": user.username, "password_hash": password_hash, "is_admin": is_admin}
#     users_data.append(new_user)
#     write_users_to_json()
#     return new_user


# Route to register a new user baru
@auth_router.post('/register', response_model=UserJSON)
async def register_user(user: UserIn):
    user_id = len(users_data) + 1
    password_hash = bcrypt.hash(user.password)
    
    is_admin = True
    
    new_user = {"id": user_id, "username": user.username, "password_hash": password_hash, "is_admin": is_admin, "tokenTicket": ""}
    users_data.append(new_user)
    write_users_to_json()
    
    
    friend_service_url = "https://holi-train-travel.grayrock-b84a6c08.australiaeast.azurecontainerapps.io/register"
    
    friend_token_data = {
        "username": user.username,
        "nama": "auvarifqi",
        "email": user.username + "@gmail.com",
        "password": user.password,
        "role": "admin"
    }
    
    try:
        # async with httpx.AsyncClient() as client:
        response = requests.post(friend_service_url, data=friend_token_data)
        
    except httpx.HTTPError as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate token in friend's service: {str(e)}")
    
    return new_user
    
    