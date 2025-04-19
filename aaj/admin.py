from django.contrib import admin, messages
from .models import Author, Signature, Domain, IntelligentModel
from .views import apply_signature 

def apply_signatures(modeladmin,request,queryset):
    try:
        for sign in queryset:
            ips_num = apply_signature(signature=sign)
            messages.success(request, f"{ips_num} ips for payload {sign.payload.payload} inserted in peste.")
    except Exception as e:
        messages.error(request, f"something wrong happend. data not inserted.")
        messages.error(request, e)

apply_signatures.short_description = "apply  signature"

class AuthorAdmin(admin.ModelAdmin):
    fields = ('name',)
    # list of fields to display in django admin
    list_display = ['name']
    # if you want django admin to show the search bar, just add this line
    search_fields = ['name']
    # to define model data list ordering
    ordering = ('name',)


class SignatureAdmin(admin.ModelAdmin):
    fields = ('name', 'author', 'payload', 'script', 'generating', 'sending_temp', 'sending_main', 'needs_input')
    # list of fields to display in django admin
    list_display = ['name', 'author', 'payload', 'insert_time', 'generating', 'sending_temp', 'sending_main',
                    'needs_input']
    # if you want django admin to show the search bar, just add this line
    search_fields = ['author', 'payload', 'name', 'insert_time', 'generating', 'sending_temp', 'sending_main']

    list_editable = ['generating', 'sending_temp', 'sending_main', 'needs_input']

    actions = [apply_signatures]


class DomainAdmin(admin.ModelAdmin):
    fields = ('domain_name', 'owner', 'generating', 'sending_temp', 'sending_main')
    # list of fields to display in django admin
    list_display = ['domain_name', 'owner', 'generating', 'sending_temp', 'sending_main']
    # if you want django admin to show the search bar, just add this line
    search_fields = ['domain_name', 'owner', 'generating', 'sending_temp', 'sending_main']
    list_editable = ['generating', 'owner', 'sending_temp', 'sending_main']

class IntelligentModelAdmin(admin.ModelAdmin):
    fields = ('name', 'author', 'payload', 'acronym', 'generating', 'sending_temp', 
    'sending_main','insert_time','update_time','file','config')
    # list of fields to display in django admin
    list_display = ['name', 'payload', 'generating', 'sending_temp', 'sending_main']
    # if you want django admin to show the search bar, just add this line
    search_fields = ['name__contains']
    list_editable = ['generating', 'sending_temp', 'sending_main']

admin.site.register(Author, AuthorAdmin)
admin.site.register(Signature, SignatureAdmin)
admin.site.register(Domain, DomainAdmin)
admin.site.register(IntelligentModel, IntelligentModelAdmin)
