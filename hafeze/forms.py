import json
import os
from pathlib import Path

from django import forms

from fil.settings import DATA_PATH

DIR = Path(__file__).resolve().parent.parent
with open(os.path.join(DIR, '.env.json'), 'r') as f:
    config = json.load(fp=f)


class IpmetaForm(forms.Form):
    ips = forms.CharField(widget=forms.Textarea(attrs={'placeholder': 'Write comma separated list of IPs'}), label='',
                          max_length=10000)
    produce = forms.BooleanField(label='Produce IPMeta?', required=False)
    days_ago = forms.IntegerField(widget=forms.NumberInput(attrs={'placeholder': 'days ago', 'class': 'inner'}),
                                  label='',
                                  required=False)
    download = forms.BooleanField(label='Download the results?', required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
