from django.contrib.auth.models import User
# me
from rest_framework import serializers

from aaj.models import Author, Signature, Domain


class apitestserializer4(serializers.Serializer):
    signature = serializers.CharField()
    unlabeled_limit = serializers.IntegerField()
    # download = serializers.BooleanField(required=False)
    date = serializers.CharField()
    input_ips = serializers.CharField()


# me

class UserSerializer(serializers.ModelSerializer):
    domains = serializers.PrimaryKeyRelatedField(many=True, queryset=Domain.objects.all())

    class Meta:
        model = User
        fields = ['id', 'username', 'domains']


class AuthorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Author
        fields = ['id', 'name']


class SignatureSerializer(serializers.ModelSerializer):
    class Meta:
        model = Signature
        fields = ['id', 'author', 'payload', 'name', 'insert_time', 'appdst', 'sizedst', 'portdst', 'domaindst',
                  'dnsdst', 'script', 'generating', 'needs_input', 'sending_temp', 'sending_main']


class DomainSerializer(serializers.ModelSerializer):
    owner = serializers.ReadOnlyField(source='owner.username')

    class Meta:
        model = Domain
        fields = ['id', 'domain_name', 'generating', 'sending_temp', 'sending_main', 'owner']
