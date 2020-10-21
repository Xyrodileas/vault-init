

class VaultInitError(Exception):
    pass

class NotEnoughtKeysError(VaultInitError):
    def __init__(self, mandatory_count, used_count):
        self.mandatory = mandatory_count
        self.used = used_count

    def __str__(self):
        return f'NotEnoughKeys excepted {self.mandatory}, used {self.used}'

class BadKeysProvided(VaultInitError):
    def __str__(self):
        return 'Provided keys cannot unseal vault server'

class BadInitParameterValue(VaultInitError):
    def __init__(self, message):
        self.message = message
    def __str__(self):
        return f'Unable to init vault server - reason given ${self.message}'
