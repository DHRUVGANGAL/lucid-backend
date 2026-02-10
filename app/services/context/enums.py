from enum import Enum

class ContextType(str, Enum):
    INITIAL_REQUIREMENT = "initial_requirement"
    CHANGE_REQUEST = "change_request"
    UNKNOWN = "unknown"
