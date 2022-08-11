import crypt
import os

#https://es.planetcalc.com/4242/
#$6$GKdY34pPeaKRiVkZ$5GqYLmzY.2J7HjDIWZMcT.Zpf5zfSdPxty5p3.vI2WScez.ieWB5GeojrzGp8OXoi1iIhtxlIeDH40FIy8pRe1

salt = os.urandom(12)
print(salt)