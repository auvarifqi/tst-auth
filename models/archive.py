from pydantic import BaseModel


# ! TIPE DATA
class ThreatData(BaseModel):
    ThreatID: int
    ThreatName: str
    ThreatType: str
    ThreatSeverity: int
    ThreatDescription: str
    ThreatSource: str
    StatusVerified: bool

class ThreatLog(BaseModel): 
    LogID: int
    ThreatID: int
    SourceID: int
    LogDescription: str
    

    
