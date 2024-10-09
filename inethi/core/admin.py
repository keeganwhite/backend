# core/admin.py

from django.contrib import admin
from .models import User, Wallet, SmartContract, FaucetSmartContract, AccountsIndexContract

# Register your models here
admin.site.register(User)
admin.site.register(Wallet)
admin.site.register(SmartContract)
admin.site.register(FaucetSmartContract)
admin.site.register(AccountsIndexContract)