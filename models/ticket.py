from typing import Optional
from pydantic import BaseModel

class Tiket(BaseModel):
    user_id: int
    penumpang_id: int
    kereta_id: int
    date_time: str
    notes: str