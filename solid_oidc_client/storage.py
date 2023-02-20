from abc import ABC, abstractmethod

class KeyValueStore(ABC):
    @abstractmethod
    def set(self, key: str, val: str) -> None:
        pass

    @abstractmethod
    def get(self, key: str) -> str:
        """gets value; throws KeyError if not existing"""
        pass

    @abstractmethod
    def has(self, key: str) -> bool:
        pass

    @abstractmethod
    def remove(self, key: str) -> None:
        pass

class MemStore(KeyValueStore):
    def __init__(self) -> None:
        self.store = {}
    
    def set(self, key: str, val: str) -> None:
        self.store[key] = val
    
    def get(self, key: str) -> str:
        return self.store[key]
    
    def has(self, key: str) -> bool:
        return key in self.store
    
    def remove(self, key: str) -> None:
        del self.store[key]