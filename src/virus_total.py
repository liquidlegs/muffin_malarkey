from src.base_api import BaseApi

class VirusTotal(BaseApi):

    def __init__(self):
        super().__init__()
        self.api_key = self.config.api_key_virus_total
        self.enabled = True

        if self.api_key == None:
            self.enabled = False