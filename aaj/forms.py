import json
import os
from pathlib import Path

DIR = Path(__file__).resolve().parent.parent
with open(os.path.join(DIR, '.env.json'), 'r') as f:
    config = json.load(fp=f)

from django import forms


class SignatureForm(forms.Form):
    signature = forms.CharField(widget=forms.Textarea(attrs={'placeholder': 'Type your code here ...'}), label='')
    unlabeled_limit = forms.IntegerField(widget=forms.NumberInput(attrs={'placeholder': 'search size'}), label='')
    download = forms.BooleanField(label='Download the results?', required=False)
    input_ips = forms.CharField(
        widget=forms.TextInput(attrs={'placeholder': 'Write comma separated list of IPs.', 'class': 'gonde inner'}),
        label='', max_length=1000, required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
